// Copyright (c) 2021 LG Electronics, Inc.
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
#include "util/JValueUtil.h"
#include "util/Logger.h"
#include "util/MSGPackUtil.h"

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

const LSMethod BugreportHandler::METHOD_TABLE[] = {
    { "getConfig",               BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "setConfig",               BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "createBug",               BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "disableCrashPopup",       BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "disableCrashReporting",   BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "doHeadlessBugReport",     BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "enableCrashPopup",        BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "enableCrashReporting",    BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "fileBugReport",           BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "fileCrashReport",         BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "getBuildMaxAge",          BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "getBugReportingConfig",   BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "getCrashReportingJira",   BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "isCrashPopupEnabled",     BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "isCrashReportingEnabled", BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "prepareBugReport",        BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "removeCredential",        BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "resetScreenshots",        BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "setBuildMaxAge",          BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "setCrashReportingJira",   BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "signInToJira",            BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "signOutFromJira",         BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "storeCredential",         BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { "takeScreenshot",          BugreportHandler::onProcessMethod, LUNA_METHOD_FLAGS_NONE },
    { nullptr, nullptr }
};

JValue BugreportHandler::Null = Object();

BugreportHandler::BugreportHandler()
    : LunaHandle("com.webos.service.bugreport")
    , m_inputInstance(NULL)
    , m_queue(NULL)
    , m_deviceListSubscriptionToken(LSMESSAGE_TOKEN_INVALID)
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
    registerCategory("/", BugreportHandler::METHOD_TABLE, NULL, NULL);
    setCategoryData("/", this);
    if (!LunaHandle::initialize(m_queue)) {
        PLUGIN_ERROR("Failed to initialize luna handle");
        rpa_queue_term(m_queue);
        rpa_queue_destroy(m_queue);
        return -1;
    }
    m_serverStatus = LunaHandle::registerServerStatus("com.webos.service.pdm",
            std::bind(&BugreportHandler::onRegisterServerStatus, this, placeholders::_1));
    // fluentbit engine calls 'onExit' when terminating, only if context is registered.
    flb_input_set_context(ins, this);
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
        const char *message = NULL;
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
    PLUGIN_INFO("%s", isConnected ? "UP" : "DOWN");
    if (isConnected) {
        LSErrorSafe lserror;
        if (!LSCall(LunaHandle::get(), "luna://com.webos.service.pdm/getAttachedNonStorageDeviceList", "{\"subscribe\":true}",
                (LSFilterFunc)BugreportHandler::onDeviceListChanged, this, &m_deviceListSubscriptionToken, &lserror)) {
            PLUGIN_ERROR("Failed in LSCall (%d) %s", lserror.error_code, lserror.message);
        }
        return true;
    }
    if (LSMESSAGE_TOKEN_INVALID == m_deviceListSubscriptionToken) {
        return true;
    }
    LSErrorSafe lserror;
    if (!LSCallCancel(LunaHandle::get(), m_deviceListSubscriptionToken, &lserror)) {
        PLUGIN_WARN("Failed in LSCallCancel (%d) %s", lserror.error_code, lserror.message);
        return true;
    }
    return true;
}

bool BugreportHandler::onDeviceListChanged(LSHandle *sh, LSMessage *message, void *ctx)
{
    PLUGIN_INFO();
    BugreportHandler* self = (BugreportHandler*)ctx;
    if (!self) {
        PLUGIN_ERROR("ctx is null");
        return false;
    }

    int oldFd = self->m_keyboardFd;
    if (oldFd != -1) {
        // always use the first found keyboard even if a new keyboard is attached
        return true;
    }
    int newFd = findKeyboardFd();
    if (oldFd != newFd) {
        if (oldFd != -1) {
            close(oldFd);
        }
        self->m_keyboardFd = newFd;
        PLUGIN_INFO("Keyboard fd : %d", newFd);
        GIOChannel *channel = g_io_channel_unix_new(newFd);
        g_io_add_watch(channel, GIOCondition(G_IO_IN|G_IO_ERR|G_IO_HUP), onKeyboardEvent, self);
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

    for (int index = 0; index < MAX_INPUT_DEVICES; index++) {
        device = "/dev/input/event" + to_string(index);
        if ((fd = open(device.c_str(), O_RDONLY)) == -1) {
            PLUGIN_DEBUG("%s is not a vaild device.", device.c_str());
            continue;
        }
        ioctl(fd, EVIOCGNAME(sizeof(name)), name);
        ioctl(fd, EVIOCGPHYS(sizeof(phys)), phys);
        PLUGIN_DEBUG("Check input device : %s (%s, %s)", device.c_str(), name, phys);
        if (strncmp(phys, "usb-", 4) == 0) {
            unsigned long evbit[NBITS(EV_CNT)];
            if (ioctl(fd, EVIOCGBIT(0, sizeof(evbit)), evbit) >= 0) {
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
                    PLUGIN_DEBUG("Found a keyboard %s:%s:%p", device.c_str(), name, evbit);
                    return fd;
                }
                PLUGIN_WARN("Unknown evbit : name (%s), phys (%s), bits (%d%d%d%d%d%d%d)", name, phys,
                        IS_BIT_SET(EV_SYN, evbit), IS_BIT_SET(EV_KEY, evbit), IS_BIT_SET(EV_REL, evbit), IS_BIT_SET(EV_ABS, evbit),
                        IS_BIT_SET(EV_MSC, evbit), IS_BIT_SET(17, evbit), IS_BIT_SET(20, evbit));
            } else {
                PLUGIN_ERROR("Error in ioctl (%d) %s", errno, strerror(errno));
            }
        }
        /* reinitialize for the next iteration */
        name[0] = '\0';
        phys[0] = '\0';
        close(fd);
    }
    return -1;
}

gboolean BugreportHandler::onKeyboardEvent(GIOChannel *channel, GIOCondition condition, gpointer data)
{
    // PLUGIN_DEBUG();
    BugreportHandler* self = (BugreportHandler*)data;
    if (!self) {
        PLUGIN_ERROR("ctx is null");
        return FALSE;
    }
    if (condition & (G_IO_HUP|G_IO_ERR)) {
        PLUGIN_INFO("G_IO_HUP or G_IO_ERR");
        g_io_channel_shutdown(channel, TRUE, NULL);
        self->m_keyboardFd = -1;
        return FALSE;
    }

    struct input_event ev[64];
    int rd, value, size = sizeof(struct input_event);
    int fd = g_io_channel_unix_get_fd(channel);

    if ((rd = read(fd, ev, size * 64)) < size) {
        // immediately close the device to prevent bugreportd from trying to
        // read key events from the invalid device.
        PLUGIN_WARN("Read %d", rd);
        g_io_channel_shutdown(channel, TRUE, NULL);
        self->m_keyboardFd = -1;
        return FALSE;
    }

    if (ev[0].value != ' ' && ev[1].type == 1) {
        // PLUGIN_DEBUG("Received key code %d(%s)", ev[1].code, ev[1].value == 1 ? "DOWN" : "UP");
        switch (ev[1].code) {
            case KEYCODE_LEFT_CTRL:
            {
                self->m_isCtrlPressed = (ev[1].value == 1) ? true : false;
                PLUGIN_DEBUG("CTRL %s", (self->m_isCtrlPressed) ? "DOWN" : "UP");
                break;
            }
            case KEYCODE_LEFT_ALT:
            {
                self->m_isAltPressed = (ev[1].value == 1) ? true : false;
                PLUGIN_DEBUG("ALT %s", (self->m_isAltPressed) ? "DOWN" : "UP");
                break;
            }
            case KEYCODE_F9:
            {
                if (ev[1].value != 1 || !self->m_isCtrlPressed || !self->m_isAltPressed)
                    break;
                self->processF9();
                break;
            }
            case KEYCODE_F10:
            {
                if (ev[1].value != 1 || !self->m_isCtrlPressed || !self->m_isAltPressed)
                    break;
                self->processF10();
                break;
            }
            case KEYCODE_F11:
            {
                if (ev[1].value != 1 || !self->m_isCtrlPressed || !self->m_isAltPressed)
                    break;
                self->processF11();
                break;
            }
            case KEYCODE_F12:
            {
                if (ev[1].value != 1 || !self->m_isCtrlPressed || !self->m_isAltPressed)
                    break;
                self->processF12();
                break;
            }
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
            (LSFilterFunc)BugreportHandler::onCreateToast,
            this,
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
            "{\"id\":\"com.palm.app.bugreport\"}",
            (LSFilterFunc)BugreportHandler::onLaunchBugreportApp,
            this,
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
    char* buffer = (char*)flb_malloc(payloadStr.length() + 1);
    if (buffer == NULL) {
        PLUGIN_ERROR("Failed in flb_malloc");
        return false;
    }
    strncpy(buffer, payloadStr.c_str(), payloadStr.length());
    buffer[payloadStr.length()] = '\0';
    PLUGIN_DEBUG("PUSH %s", buffer);
    return rpa_queue_push(m_queue, (void*)buffer);
}

bool BugreportHandler::onProcessMethod(LSHandle *sh, LSMessage *msg, void *ctx)
{
    typedef ErrCode (BugreportHandler::*MethodProcessor)(JValue&, JValue&);
    static map<string, MethodProcessor> methods = {
            { "/getConfig",               &BugreportHandler::getConfig },
            { "/setConfig",               &BugreportHandler::setConfig },
            { "/createBug",               &BugreportHandler::createBug },
            { "/disableCrashPopup",       &BugreportHandler::processDeprecatedMethod },
            { "/disableCrashReporting",   &BugreportHandler::processDeprecatedMethod },
            { "/doHeadlessBugReport",     &BugreportHandler::processF12 },
            { "/enableCrashPopup",        &BugreportHandler::processDeprecatedMethod },
            { "/enableCrashReporting",    &BugreportHandler::processDeprecatedMethod },
            { "/fileBugReport",           &BugreportHandler::createBug },
            { "/fileCrashReport",         &BugreportHandler::processDeprecatedMethod },
            { "/getBuildMaxAge",          &BugreportHandler::processDeprecatedMethod },
            { "/getBugReportingConfig",   &BugreportHandler::processDeprecatedMethod },
            { "/getCrashReportingJira",   &BugreportHandler::processDeprecatedMethod },
            { "/isCrashPopupEnabled",     &BugreportHandler::processDeprecatedMethod },
            { "/isCrashReportingEnabled", &BugreportHandler::processDeprecatedMethod },
            { "/prepareBugReport",        &BugreportHandler::processF11 },
            { "/removeCredential",        &BugreportHandler::processDeprecatedMethod },
            { "/resetScreenshots",        &BugreportHandler::processF10 },
            { "/setBuildMaxAge",          &BugreportHandler::processDeprecatedMethod },
            { "/setCrashReportingJira",   &BugreportHandler::processDeprecatedMethod },
            { "/signInToJira",            &BugreportHandler::setConfig },
            { "/signOutFromJira",         &BugreportHandler::processDeprecatedMethod },
            { "/storeCredential",         &BugreportHandler::setConfig },
            { "/takeScreenshot",          &BugreportHandler::processF9 },
    };
    BugreportHandler* self = (BugreportHandler*)ctx;
    if (self == NULL) {
        PLUGIN_ERROR("ctx is null");
        return false;
    }
    Message request(msg);
    const char* sender = request.getSenderServiceName() != NULL ? request.getSenderServiceName() : request.getApplicationID();
    PLUGIN_INFO("Kind(%s) Sender(%s) %s",  request.getKind(), sender, request.getPayload());
    JValue requestPayload = JDomParser::fromString(request.getPayload());
    JValue responsePayload = Object();
    ErrCode errCode = ErrCode_NONE;
    MethodProcessor mp;
    auto it = methods.find(request.getKind());
    if (it == methods.end()) {
        PLUGIN_ERROR("Method not found : %s", request.getKind());
        errCode = ErrCode_INTERNAL_ERROR;
        goto Done;
    }
    if (requestPayload.isNull()) {
        PLUGIN_ERROR("Json parse error : %s", request.getPayload());
        errCode = ErrCode_INVALID_REQUEST_PARAMS;
        goto Done;
    }
    mp = it->second;
    errCode = (self->*mp)(requestPayload, responsePayload);

Done:
    if (ErrCode_NONE != errCode) {
        responsePayload.put("returnValue", false);
        responsePayload.put("errorCode", errCode);
        responsePayload.put("errorText", strerror(errCode));
    } else {
        responsePayload.put("returnValue", true);
    }
    try {
        request.respond(responsePayload.stringify().c_str());
    } catch(exception& e) {
        PLUGIN_ERROR("Failed to respond: %s", e.what());
        return false;
    }
    PLUGIN_INFO("Kind(%s) Sender(%s) %s",  request.getKind(), sender, responsePayload.stringify().c_str());
    return true;
}

ErrCode BugreportHandler::getConfig(JValue& requestPayload, JValue& responsePayload)
{
    JValue config = m_configManager.getConfig();
    config.put("screenshots", m_screenshotManager.toJson());
    responsePayload.put("config", config);
    return ErrCode_NONE;
}

ErrCode BugreportHandler::setConfig(JValue& requestPayload, JValue& responsePayload)
{
    string username, password;
    if (!JValueUtil::getValue(requestPayload, "username", username)) {
        PLUGIN_ERROR("username is required");
        return ErrCode_INVALID_REQUEST_PARAMS;
    }
    if (!JValueUtil::getValue(requestPayload, "password", password)) {
        PLUGIN_ERROR("password is required");
        return ErrCode_INVALID_REQUEST_PARAMS;
    }
    if (!m_configManager.setConfig(username, password)) {
        return ErrCode_INTERNAL_ERROR;
    }
    return ErrCode_NONE;
}

ErrCode BugreportHandler::createBug(JValue& requestPayload, JValue& responsePayload)
{
    ErrCode errCode = ErrCode_NONE;
    string summary, priority, reproducibility;
    JValue screenshots = Array();
    string username, password;
    JValue config = Object();
    JValue payload = Object();
    string payloadStr;
    char* buffer;
    if (!JValueUtil::getValue(requestPayload, "summary", summary)) {
        PLUGIN_ERROR("summary is required");
        return ErrCode_INVALID_REQUEST_PARAMS;
    }
    payload.put("summary", summary);
    if (JValueUtil::getValue(requestPayload, "priority", priority)) {
        payload.put("priority", priority);
    }
    if (JValueUtil::getValue(requestPayload, "reproducibility", reproducibility)) {
        payload.put("reproducibility", reproducibility);
    }
    if (JValueUtil::getValue(requestPayload, "screenshots", screenshots) && screenshots.isArray()) {
        string screenshotStr = "";
        for (const JValue& screenshot : screenshots.items()) {
            if (!screenshot.isString())
                continue;
            screenshotStr += screenshot.asString() + " ";
        }
        if (!screenshotStr.empty()) {
            payload.put("upload-files", screenshotStr.erase(screenshotStr.length()-1));
        }
    }
    if (!m_configManager.getUsername().empty()) {
        payload.put("username", m_configManager.getUsername());
    }
    if (!m_configManager.getPassword().empty()) {
        payload.put("password", m_configManager.getPassword());
    }
    if (!pushToRpaQueue(payload)) {
        PLUGIN_ERROR("Failed in rpa_queue_push");
        return ErrCode_INTERNAL_ERROR;
    }
    return ErrCode_NONE;
}

ErrCode BugreportHandler::processDeprecatedMethod(JValue&, JValue&)
{
    return ErrCode_DEPRECATED_METHOD;
}

ErrCode BugreportHandler::processF9(JValue&, JValue&)
{
    PLUGIN_INFO("[CTRL][ALT][F9] Take screenshot");
    string screenshotFile = m_screenshotManager.takeScreenshot();
    if (screenshotFile.empty())
        createToast("Taking screenshot fails!");
    else
        createToast(screenshotFile + " captured!");
    return ErrCode_NONE;
}

ErrCode BugreportHandler::processF10(JValue&, JValue&)
{
    PLUGIN_INFO("[CTRL][ALT][F10] Remove screenshot");
    m_screenshotManager.removeAll();
    createToast("Screenshots removed!");
    return ErrCode_NONE;
}

ErrCode BugreportHandler::processF11(JValue&, JValue&)
{
    PLUGIN_INFO("[CTRL][ALT][F11] Launch bugreport app");
    launchBugreportApp();
    return ErrCode_NONE;
}

ErrCode BugreportHandler::processF12(JValue&, JValue&)
{
    PLUGIN_INFO("[CTRL][ALT][F12] Create bug");
    if (m_screenshotManager.getScreenshots().empty())
        m_screenshotManager.takeScreenshot();
    JValue payload = Object();
    payload.put("summary", m_configManager.generateJiraSummary());
    payload.put("upload-files", m_screenshotManager.toString());
    if (!pushToRpaQueue(payload)) {
        PLUGIN_ERROR("Failed in rpa_queue_push");
    }
    return ErrCode_NONE;
}
