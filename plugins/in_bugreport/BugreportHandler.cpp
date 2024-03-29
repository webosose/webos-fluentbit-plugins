// Copyright (c) 2021-2023 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#include "BugreportHandler.h"

#include <fcntl.h>
#include <functional>
#include <linux/input.h>
#include <list>
#include <pthread.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <msgpack.h>

#include "Environment.h"
#include "FluentBit.h"
#include "util/ErrCode.h"
#include "util/File.h"
#include "util/JValueUtil.h"
#include "util/Logger.h"
#include "util/MSGPackUtil.h"
#include "util/StringUtil.h"

#define DEFAULT_QUEUE_CAPACITY  100
#define DEFAULT_INTERVAL_SEC    1
#define DEFAULT_INTERVAL_NSEC   0

#define MAX_INPUT_DEVICES       20

#define BITS_PER_LONG           (sizeof(long) * 8)
#define NBITS(x)                ((((x)-1)/BITS_PER_LONG)+1)
#define OFFSET(x)               ((x)%BITS_PER_LONG)
#define LONG(x)                 ((x)/BITS_PER_LONG)
#define IS_BIT_SET(bit, array)  ((array[LONG(bit)] >> OFFSET(bit)) & 1)

#define KEYCODE_LEFT_CTRL       29
#define KEYCODE_LEFT_ALT        56
#define KEYCODE_LEFT_SHIFT      42

#define KEYCODE_F9              67
#define KEYCODE_F10             68
#define KEYCODE_F11             87
#define KEYCODE_F12             88

const char* TicketCreated = "Ticket created : ";

extern "C" int initBugreportHandler(struct flb_input_instance *ins, struct flb_config *config, void *data)
{
    return BugreportHandler::getInstance().onInit(ins, config, data);
}

extern "C" int exitBugreportHandler(void *context, struct flb_config *config)
{
    return BugreportHandler::getInstance().onExit(context, config);
}

extern "C" int collectBugreport(struct flb_input_instance *ins, struct flb_config *config, void *context)
{
    return BugreportHandler::getInstance().onCollect(ins, config, context);
}

extern "C" bool getConfig(LSHandle *sh, LSMessage *msg, void *ctx)
{
    return BugreportHandler::getInstance().getConfig(sh, msg, ctx);
}

extern "C" bool setConfig(LSHandle *sh, LSMessage *msg, void *ctx)
{
    return BugreportHandler::getInstance().setConfig(sh, msg, ctx);
}

extern "C" bool createBug(LSHandle *sh, LSMessage *msg, void *ctx)
{
    return BugreportHandler::getInstance().createBug(sh, msg, ctx);
}

extern "C" gboolean onKeyboardEvent(GIOChannel *channel, GIOCondition condition, gpointer data)
{
    return BugreportHandler::getInstance().onKeyboardEvent(channel, condition, data);
}

extern "C" bool onCreateToast(LSHandle *sh, LSMessage *message, void *ctx)
{
    return BugreportHandler::getInstance().onCreateToast(sh, message, ctx);
}

extern "C" bool onLaunchBugreportApp(LSHandle *sh, LSMessage *message, void *ctx)
{
    return BugreportHandler::getInstance().onLaunchBugreportApp(sh, message, ctx);
}

const LSMethod BugreportHandler::METHOD_TABLE[] = {
    { "getConfig",               ::getConfig, LUNA_METHOD_FLAGS_NONE },
    { "setConfig",               ::setConfig, LUNA_METHOD_FLAGS_NONE },
    { "createBug",               ::createBug, LUNA_METHOD_FLAGS_NONE },
    { nullptr, nullptr },
};

JValue BugreportHandler::Null = Object();

BugreportHandler& BugreportHandler::getInstance()
{
    static BugreportHandler s_instance;
    return s_instance;
}

BugreportHandler::BugreportHandler()
    : LunaHandle("com.webos.service.bugreport")
    , m_inputInstance(NULL)
    , m_queue(NULL)
    , m_keyboardFd(-1)
    , m_isAltPressed(false)
    , m_isCtrlPressed(false)
{
    PLUGIN_INFO();
    setClassName("BugreportHandler");
}

BugreportHandler::~BugreportHandler()
{
    PLUGIN_INFO();
}

int BugreportHandler::onInit(struct flb_input_instance *ins, struct flb_config *config, void *data)
{
    PLUGIN_INFO();
    m_inputInstance = ins;

    if (!m_configManager.initialize()) {
        PLUGIN_ERROR("Failed to initialize config manager");
        return -1;
    }
    if (!m_screenshotManager.initialize(this)) {
        PLUGIN_ERROR("Failed to initialize screenshot manager");
        return -1;
    }
    if (!rpa_queue_create(&m_queue, DEFAULT_QUEUE_CAPACITY)) {
        PLUGIN_ERROR("Failed in rpa_queue_create");
        return -1;
    }
    try {
        registerCategory("/", BugreportHandler::METHOD_TABLE, NULL, NULL);
        setCategoryData("/", this);
    } catch (LS::Error& lserror) {
        PLUGIN_ERROR("Failed to setCategoryData; %s", lserror.what());
        return -1;
    }
    if (!LunaHandle::initialize(m_queue)) {
        PLUGIN_ERROR("Failed to initialize luna handle");
        rpa_queue_term(m_queue);
        rpa_queue_destroy(m_queue);
        return -1;
    }
    try {
        m_serverStatus = LunaHandle::registerServerStatus("com.webos.service.pdm",
                std::bind(&BugreportHandler::onRegisterServerStatus, this, placeholders::_1));
    } catch (LS::Error& lserror) {
        PLUGIN_ERROR("Failed to registerServerStatus com.webos.service.pdm; %s", lserror.what());
        return -1;
    }

    // fluentbit engine calls 'onExit' when terminating, only if context is registered.
    flb_input_set_context(ins, ins);
    if (flb_input_set_collector_time(ins, collectBugreport, DEFAULT_INTERVAL_SEC, DEFAULT_INTERVAL_NSEC, config) == -1) {
        PLUGIN_ERROR("Failed in flb_input_set_collector_time");
        rpa_queue_term(m_queue);
        rpa_queue_destroy(m_queue);
        return -1;
    }
    return 0;
}

int BugreportHandler::onExit(void *context, struct flb_config *config)
{
    PLUGIN_INFO();
    LunaHandle::finalize();
    rpa_queue_term(m_queue);
    rpa_queue_destroy(m_queue);
    m_screenshotManager.finalize();
    m_configManager.finalize();
    return 0;
}

int BugreportHandler::onCollect(struct flb_input_instance *ins, struct flb_config *config, void *context)
{
    msgpack_packer packer;
    msgpack_sbuffer sbuffer;
    while (true) {
        char *message = NULL;
        if (!rpa_queue_timedpop(m_queue, (void **)&message, RPA_WAIT_NONE))
            break;
        PLUGIN_DEBUG("POP %s", message);
        JValue json = pbnjson::JDomParser::fromString(message);
        if (json.isNull() || !json.isValid()) {
            PLUGIN_ERROR("Failed to parse message");
            flb_free((void*)message);
            continue;
        }
        msgpack_sbuffer_init(&sbuffer);
        msgpack_packer_init(&packer, &sbuffer, msgpack_sbuffer_write);

        msgpack_pack_array(&packer, 2);
        flb_pack_time_now(&packer);
        MSGPackUtil::putValue(&packer, "", json);

        flb_input_chunk_append_raw(ins, NULL, 0, sbuffer.data, sbuffer.size);
        msgpack_sbuffer_destroy(&sbuffer);
        flb_free((void*)message);
    }
    return 0;
}

bool BugreportHandler::onRegisterServerStatus(bool isConnected)
{
    static string method = "luna://com.webos.service.pdm/getAttachedNonStorageDeviceList";
    PLUGIN_INFO("%s", isConnected ? "UP" : "DOWN");
    if (isConnected) {
        JValue requestPayload = Object();
        requestPayload.put("subscribe", true);
        m_getAttachedNonStorageDeviceListCall = callMultiReply(
                method.c_str(),
                requestPayload.stringify().c_str(),
                BugreportHandler::onGetAttachedNonStorageDeviceList,
                NULL
        );
    } else {
        m_getAttachedNonStorageDeviceListCall.cancel();
    }
    return true;
}

bool BugreportHandler::onGetAttachedNonStorageDeviceList(LSHandle *sh, LSMessage *message, void *ctx)
{
    PLUGIN_INFO();
    BugreportHandler& self = BugreportHandler::getInstance();

    int oldFd = self.m_keyboardFd;
    if (oldFd != -1) {
        // always use the first found keyboard even if a new keyboard is attached
        return true;
    }
    int newFd = findKeyboardFd();
    if (oldFd != newFd) {
        self.m_keyboardFd = newFd;
        PLUGIN_INFO("Keyboard fd : %d", newFd);
        GIOChannel *channel = g_io_channel_unix_new(newFd);
        g_io_add_watch(channel, GIOCondition(G_IO_IN|G_IO_ERR|G_IO_HUP), ::onKeyboardEvent, NULL);
        g_io_channel_unref(channel);
    }
    return true;
}

int BugreportHandler::findKeyboardFd()
{
    string device;
    char name[256];
    char phys[256];
    int fd = -1;
    char errbuf[1024];

    for (int index = 0; index < MAX_INPUT_DEVICES; index++) {
        device = "/dev/input/event" + to_string(index);
        if ((fd = open(device.c_str(), O_RDONLY)) == -1) {
            PLUGIN_DEBUG("%s is not a vaild device.", device.c_str());
            continue;
        }
        errno = 0;
        if (ioctl(fd, EVIOCGNAME(sizeof(name)), name) == -1) {
            int ec = errno;
            PLUGIN_DEBUG("Error in ioctl EVIOCGNAME for (%d) %s", ec, strerror_r(ec, errbuf, sizeof(errbuf)));
            close(fd);
            continue;
        }
        errno = 0;
        if (ioctl(fd, EVIOCGPHYS(sizeof(phys)), phys) == -1) {
            int ec = errno;
            PLUGIN_DEBUG("Error in ioctl EVIOCGPHYS for (%d) %s", ec, strerror_r(ec, errbuf, sizeof(errbuf)));
            close(fd);
            continue;
        }
        PLUGIN_DEBUG("Check input device : %s (%s, %s)", device.c_str(), name, phys);
        if (strncmp(phys, "usb-", 4) != 0) {
            close(fd);
            continue;
        }
        unsigned long evbit[NBITS(EV_CNT)];
        errno = 0;
        if (ioctl(fd, EVIOCGBIT(0, sizeof(evbit)), evbit) == -1) {
            int ec = errno;
            PLUGIN_ERROR("Error in ioctl EVIOCGBIT for (%d) %s", ec, strerror_r(ec, errbuf, sizeof(errbuf)));
            close(fd);
            continue;
        }
        /* USB keyboard's EV is always 120013 (0000 0000 0001 0010 0000 0000 0001 0011)
         * It might be ok to check the 17th and 20th bit because any other devices might not set both bits.
         * But for safety, this code checks bits (0, 1, 2, 3, 4, 17, 20).
         */
        if (IS_BIT_SET(EV_SYN, evbit) && // bit 0
                IS_BIT_SET(EV_KEY, evbit) && // bit 1
                !IS_BIT_SET(EV_REL, evbit) && // bit 2
                !IS_BIT_SET(EV_ABS, evbit) && // bit 3
                IS_BIT_SET(EV_MSC, evbit) && // bit 4
                IS_BIT_SET(17, evbit) && // bit 17
                IS_BIT_SET(20, evbit))   // bit 20
        {
            PLUGIN_INFO("Found a keyboard %s:%s:%p", device.c_str(), name, evbit);
            return fd;
        }
        PLUGIN_WARN("Unknown evbit : name (%s), phys (%s), bits (%d%d%d%d%d%d%d)", name, phys,
                IS_BIT_SET(EV_SYN, evbit), IS_BIT_SET(EV_KEY, evbit), IS_BIT_SET(EV_REL, evbit), IS_BIT_SET(EV_ABS, evbit),
                IS_BIT_SET(EV_MSC, evbit), IS_BIT_SET(17, evbit), IS_BIT_SET(20, evbit));
        close(fd);
    }
    return -1;
}

gboolean BugreportHandler::onKeyboardEvent(GIOChannel *channel, GIOCondition condition, gpointer data)
{
    // PLUGIN_DEBUG();
    BugreportHandler& self = BugreportHandler::getInstance();
    if (condition & (G_IO_HUP|G_IO_ERR)) {
        PLUGIN_INFO("G_IO_HUP or G_IO_ERR");
        g_io_channel_shutdown(channel, TRUE, NULL);
        self.m_keyboardFd = -1;
        return FALSE;
    }

    struct input_event ev[64];
    ssize_t rd;
    int value;
    size_t size = sizeof(struct input_event);
    int fd = g_io_channel_unix_get_fd(channel);

    if ((rd = read(fd, ev, size * 64)) < 0 || rd < size) {
        // immediately close the device to prevent bugreportd from trying to
        // read key events from the invalid device.
        PLUGIN_WARN("Read %d", rd);
        g_io_channel_shutdown(channel, TRUE, NULL);
        self.m_keyboardFd = -1;
        return FALSE;
    }

    if (ev[0].value != ' ' && ev[1].type == 1) {
        // PLUGIN_DEBUG("Received key code %d(%s)", ev[1].code, ev[1].value == 1 ? "DOWN" : "UP");
        switch (ev[1].code) {
            case KEYCODE_LEFT_CTRL:
                self.m_isCtrlPressed = (ev[1].value == 1) ? true : false;
                PLUGIN_DEBUG("CTRL %s", (self.m_isCtrlPressed) ? "DOWN" : "UP");
                break;
            case KEYCODE_LEFT_ALT:
                self.m_isAltPressed = (ev[1].value == 1) ? true : false;
                PLUGIN_DEBUG("ALT %s", (self.m_isAltPressed) ? "DOWN" : "UP");
                break;
            case KEYCODE_F9:
                if (ev[1].value != 1 || !self.m_isCtrlPressed || !self.m_isAltPressed)
                    break;
                self.processF9();
                break;
            case KEYCODE_F10:
                if (ev[1].value != 1 || !self.m_isCtrlPressed || !self.m_isAltPressed)
                    break;
                self.processF10();
                break;
            case KEYCODE_F11:
                if (ev[1].value != 1 || !self.m_isCtrlPressed || !self.m_isAltPressed)
                    break;
                self.processF11();
                break;
            case KEYCODE_F12:
                if (ev[1].value != 1 || !self.m_isCtrlPressed || !self.m_isAltPressed)
                    break;
                self.processF12();
                break;
            default:
                break;
        }
    }
    return TRUE;
}

void BugreportHandler::createToast(const string& message)
{
    PLUGIN_INFO("%s", message.c_str());
    pbnjson::JValue payload = Object();
    payload.put("sourceId", "com.webos.service.bugreport");
    payload.put("message", message);

    LSErrorSafe lserror;
    if (!LSCallOneReply(LunaHandle::get(),
            "luna://com.webos.notification/createToast",
            payload.stringify().c_str(),
            ::onCreateToast,
            NULL,
            NULL,
            &lserror)) {
        PLUGIN_ERROR("Failed in LSCall (%d) %s", lserror.error_code, lserror.message);
    }
}

bool BugreportHandler::onCreateToast(LSHandle *sh, LSMessage *message, void *ctx)
{
    PLUGIN_INFO("%s", LSMessageGetPayload(message));
    return true;
}

void BugreportHandler::launchBugreportApp()
{
    PLUGIN_INFO();
    LSErrorSafe lserror;
    if (!LSCallOneReply(LunaHandle::get(),
            "luna://com.webos.service.applicationmanager/launch",
            "{\"id\":\"com.webos.app.bugreport\"}",
            ::onLaunchBugreportApp,
            NULL,
            NULL,
            &lserror)) {
        PLUGIN_ERROR("Failed in LSCall (%d) %s", lserror.error_code, lserror.message);
    }
}

bool BugreportHandler::onLaunchBugreportApp(LSHandle *sh, LSMessage *message, void *ctx)
{
    PLUGIN_INFO("%s", LSMessageGetPayload(message));
    return true;
}

bool BugreportHandler::pushToRpaQueue(JValue payload)
{
    string payloadStr = payload.stringify();
    size_t length = payloadStr.length();
    if (SIZE_MAX - length < 1) {
        PLUGIN_ERROR("Wrong payload length");
        return false;
    }
    char* buffer = (char*)flb_malloc(length + 1);
    if (buffer == NULL) {
        PLUGIN_ERROR("Failed in flb_malloc");
        return false;
    }
    strncpy(buffer, payloadStr.c_str(), length);
    buffer[length] = '\0';
    PLUGIN_DEBUG("PUSH %s", buffer);
    return rpa_queue_push(m_queue, (void*)buffer);
}

ErrCode BugreportHandler::parseRequest(Message& request, JValue& requestPayload, void* ctx)
{
    BugreportHandler* self = (BugreportHandler*)ctx;
    if (self == NULL) {
        PLUGIN_ERROR("ctx is null");
        return ErrCode_INTERNAL_ERROR;
    }
    const char* sender = request.getSenderServiceName() != NULL ? request.getSenderServiceName() : request.getApplicationID();
    PLUGIN_INFO("Kind(%s) Sender(%s) %s",  request.getKind(), sender, request.getPayload());
    requestPayload = JDomParser::fromString(request.getPayload());
    if (requestPayload.isNull()) {
        PLUGIN_ERROR("Json parse error : %s", request.getPayload());
        return ErrCode_INVALID_REQUEST_PARAMS;
    }
    return ErrCode_NONE;
}

bool BugreportHandler::sendResponse(Message& request, ErrCode errCode)
{
    JValue responsePayload = Object();
    if (ErrCode_NONE != errCode) {
        responsePayload.put("returnValue", false);
        responsePayload.put("errorCode", errCode);
        responsePayload.put("errorText", ErrCodeToStr(errCode));
    } else {
        responsePayload.put("returnValue", true);
    }
    return sendResponse(request, responsePayload.stringify());
}

bool BugreportHandler::sendResponse(Message& request, const string& responsePayload)
{
    try {
        request.respond(responsePayload.c_str());
    } catch(exception& e) {
        PLUGIN_ERROR("Failed to respond: %s", e.what());
        return false;
    }
    PLUGIN_INFO("Kind(%s) %s",  request.getKind(), responsePayload.c_str());
    return true;
}

bool BugreportHandler::getConfig(LSHandle *sh, LSMessage *msg, void *ctx)
{
    ErrCode errCode = ErrCode_NONE;
    Message request(msg);
    JValue requestPayload = Object();
    if (ErrCode_NONE != (errCode = parseRequest(request, requestPayload, ctx))) {
        return sendResponse(request, errCode);
    }

    BugreportHandler* self = (BugreportHandler*)ctx;
    JValue responsePayload = self->m_configManager.getConfig();
    responsePayload.put("screenshots", self->m_screenshotManager.toJson());
    responsePayload.put("returnValue", true);
    return sendResponse(request, responsePayload.stringify());
}

bool BugreportHandler::setConfig(LSHandle *sh, LSMessage *msg, void *ctx)
{
    ErrCode errCode = ErrCode_NONE;
    Message request(msg);
    JValue requestPayload = Object();
    if (ErrCode_NONE != (errCode = parseRequest(request, requestPayload, ctx))) {
        return sendResponse(request, errCode);
    }

    BugreportHandler* self = (BugreportHandler*)ctx;
    string username, b64encodedPassword;
    JValue account = Object();
    if (JValueUtil::getValue(requestPayload, "account", account)) {
        if (ErrCode_NONE != (errCode = self->m_configManager.setAccount(account))) {
            return sendResponse(request, errCode);
        }
    }
    return sendResponse(request, ErrCode_NONE);
}

bool BugreportHandler::createBug(LSHandle *sh, LSMessage *msg, void *ctx)
{
    ErrCode errCode = ErrCode_NONE;
    Message request(msg);
    JValue requestPayload = Object();
    if (ErrCode_NONE != (errCode = parseRequest(request, requestPayload, ctx))) {
        return sendResponse(request, errCode);
    }

    BugreportHandler* self = (BugreportHandler*)ctx;
    string summary, description, priority, reproducibility, issuetype;
    JValue screenshots = Array();
    string screenshotStr;
    list<string> screenshotPaths;
    if (!JValueUtil::getValue(requestPayload, "summary", summary)) {
        PLUGIN_ERROR("summary is required");
        return sendResponse(request, ErrCode_INVALID_REQUEST_PARAMS);
    }
    (void) JValueUtil::getValue(requestPayload, "description", description);
    (void) JValueUtil::getValue(requestPayload, "priority", priority);
    (void) JValueUtil::getValue(requestPayload, "reproducibility", reproducibility);
    (void) JValueUtil::getValue(requestPayload, "issuetype", issuetype);
    if (JValueUtil::getValue(requestPayload, "screenshots", screenshots) && screenshots.isArray()) {
        for (const JValue& screenshot : screenshots.items()) {
            if (!screenshot.isString())
                continue;
            screenshotStr += screenshot.asString() + " ";
            screenshotPaths.emplace_back(screenshot.asString());
        }
        if (!screenshotStr.empty()) {
            screenshotStr.erase(screenshotStr.length()-1);
        }
    }

    // TODO We need to pass data to output plugin. There are no output plugins at this time.

    string key;
    if (ErrCode_NONE != (errCode = createTicket(summary, description, priority, reproducibility, issuetype, screenshotStr, key))) {
        return sendResponse(request, errCode);
    }
    for (const string& screenshotPath_s : screenshotPaths) {
        const char* screenshotPath = screenshotPath_s.c_str();
        errno = 0;
        if (-1 == unlink(screenshotPath)) {
            int ec = errno;
            char errbuf[1024];
            PLUGIN_WARN("Failed to remove %s : %s", screenshotPath, strerror_r(ec, errbuf, sizeof(errbuf)));
            continue;
        }
        PLUGIN_INFO("Removed %s", screenshotPath);
    }
    JValue responsePayload = Object();
    responsePayload.put("key", key);
    responsePayload.put("returnValue", true);
    return sendResponse(request, responsePayload.stringify());
}

ErrCode BugreportHandler::createTicket(const string& summary, const string& description, const string& priority, const string& reproducibility, const string& issuetype, const string& uploadFiles, string& key)
{
    string command = "webos_issue.py --log-level info --enable-popup --summary \'" + summary + "\' "
                   + (description.empty() ? "" : "--description '" + description + "' ")
                   + (priority.empty() ? "" : "--priority " + priority + " ")
                   + (reproducibility.empty() ? "" : "--reproducibility \"" + reproducibility + "\" ")
                   + (issuetype.empty() ? "" : "--issuetype \"" + issuetype + "\" ")
                   + (uploadFiles.empty() ? "" : "--upload-files " + uploadFiles);
    PLUGIN_INFO("%s", command.c_str());
    string stdout, stderr, errmsg;
    int ret;
    gchar** lines;
    if (!File::popen(command, stdout, stderr, &ret, errmsg)) {
        PLUGIN_WARN("Failed to webos_issue.py : %s", errmsg.c_str());
        return ErrCode_FORK_FAILED;
    }
    if (!stderr.empty()) {
        PLUGIN_WARN(" ! %s", stderr.c_str());
    }
    if (!stdout.empty()) {
        lines = g_strsplit(stdout.c_str(), "\n", 0);
        guint len = g_strv_length(lines);
        for (guint i = 0; i < len; i++) {
            PLUGIN_INFO("> %s", lines[i]);
            if (strncmp(lines[i], TicketCreated, strlen(TicketCreated)))
                continue;
            string tmp = lines[i] + strlen(TicketCreated);
            key = StringUtil::trim(tmp);
        }
        g_strfreev(lines);
    }

    if (!WIFEXITED(ret) || WEXITSTATUS(ret)) {
        PLUGIN_ERROR("Command terminated with failure : Return code (0x%x), exited (%d), exit-status (%d)", ret, WIFEXITED(ret), WEXITSTATUS(ret));
        return ErrCode_INTERNAL_ERROR;
    }
    PLUGIN_INFO("Done [%s]", key.c_str());
    return ErrCode_NONE;
}

ErrCode BugreportHandler::processF9()
{
    PLUGIN_INFO("[CTRL][ALT][F9] Take screenshot");
    string screenshotFile = m_screenshotManager.captureCompositorOutput();
    if (screenshotFile.empty())
        createToast("Taking screenshot fails!");
    else
        createToast(screenshotFile + " captured!");
    return ErrCode_NONE;
}

ErrCode BugreportHandler::processF10()
{
    PLUGIN_INFO("[CTRL][ALT][F10] Remove screenshot");
    m_screenshotManager.removeScreenshots();
    createToast("Screenshots removed!");
    return ErrCode_NONE;
}

ErrCode BugreportHandler::processF11()
{
    PLUGIN_INFO("[CTRL][ALT][F11] Launch bugreport app");
    launchBugreportApp();
    return ErrCode_NONE;
}

ErrCode BugreportHandler::processF12()
{
    PLUGIN_INFO("[CTRL][ALT][F12] Create bug");
    m_screenshotManager.captureCompositorOutput();
    ErrCode errCode = ErrCode_NONE;
    string key;
    if (ErrCode_NONE == (errCode = createTicket(m_configManager.getSummary(), "", "", "", "", m_screenshotManager.toString(), key))) {
        m_screenshotManager.removeScreenshots();
    }
    return errCode;
}
