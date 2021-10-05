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
#include <linux/input.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <msgpack.h>

#include "FluentBit.h"
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

const LSMethod BugreportHandler::METHOD_TABLE[2] = {
    { "test", BugreportHandler::_test, LUNA_METHOD_FLAGS_NONE },
    { nullptr, nullptr }
};

BugreportHandler::BugreportHandler()
    : LunaHandle("com.webos.rdx.bugreport")
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

    if (!rpa_queue_create(&m_queue, DEFAULT_QUEUE_CAPACITY)) {
        PLUGIN_ERROR("Failed in rpa_queue_create");
        return -1;
    }
    if (!LunaHandle::initialize(m_queue, "/", BugreportHandler::METHOD_TABLE)) {
        PLUGIN_ERROR("Failed to initialize luna handle");
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
        pbnjson::JValue json = pbnjson::JDomParser::fromString(message);
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
        PLUGIN_DEBUG("Received key code %d(%s)", ev[1].code, ev[1].value == 1 ? "DOWN" : "UP");
        switch (ev[1].code) {
            case KEYCODE_LEFT_CTRL:
                self->m_isCtrlPressed = (ev[1].value == 1) ? true : false;
                PLUGIN_DEBUG("CTRL %s", (self->m_isCtrlPressed) ? "DOWN" : "UP");
                break;
            case KEYCODE_LEFT_ALT:
                self->m_isAltPressed = (ev[1].value == 1) ? true : false;
                PLUGIN_DEBUG("ALT %s", (self->m_isAltPressed) ? "DOWN" : "UP");
                break;
            case KEYCODE_F11:
                if (ev[1].value == 1 && self->m_isCtrlPressed) {
                    if (self->m_isAltPressed) {
                        PLUGIN_INFO("CTRL + ALT + F11");
                        // push message in queue
                        string str = "{\"key\": \"test message\"}";
                        char* buffer = (char*)flb_malloc(str.length() + 1);
                        if (buffer == NULL) {
                            PLUGIN_ERROR("Failed in flb_malloc");
                            return true;
                        }
                        strncpy(buffer, str.c_str(), str.length());
                        buffer[str.length()] = '\0';
                        PLUGIN_DEBUG("PUSH %s", buffer);
                        rpa_queue_push(self->m_queue, (void*)buffer);
                    } else {
                        PLUGIN_INFO("CTRL + F11");
                    }
                }
                break;
            case KEYCODE_F9:
                if (ev[1].value == 1 && self->m_isCtrlPressed) {
                    if (self->m_isAltPressed) {
                        PLUGIN_INFO("CTRL + ALT + F9");
                    } else {
                        PLUGIN_INFO("CTRL + F9");
                        PLUGIN_INFO("Take a screenshot into /tmp/capture/screenshot<N>.jpg");
                        self->takeScreenshot();
                    }
                }
                break;
            default:
                break;
        }
    }
    return TRUE;
}

void BugreportHandler::takeScreenshot()
{
    PLUGIN_INFO();
    string filepath = "/tmp/capture/test.jpg";
    pbnjson::JValue payload = Object();
    payload.put("output", filepath);
    payload.put("format", "JPG");

    LSErrorSafe lserror;
    if (!LSCallOneReply(LunaHandle::get(),
            "luna://com.webos.surfacemanager/captureCompositorOutput",
            payload.stringify().c_str(),
            (LSFilterFunc)BugreportHandler::onTakeScreenshot,
            this,
            NULL,
            &lserror)) {
        PLUGIN_ERROR("Failed in LSCall (%d) %s", lserror.error_code, lserror.message);
    }
}

bool BugreportHandler::onTakeScreenshot(LSHandle *sh, LSMessage *message, void *ctx)
{
    PLUGIN_INFO("%s", LSMessageGetPayload(message));
    return true;
}

bool BugreportHandler::test(LSMessage &message)
{
    Message request(&message);
    const char* sender = request.getSenderServiceName() != NULL ? request.getSenderServiceName() : request.getApplicationID();
    PLUGIN_INFO("API-Req(%s) Sender(%s) %s",  request.getKind(), sender, LSMessageGetPayload(&message));

    pbnjson::JValue responsePayload = pbnjson::Object();
    pbnjson::JValue requestPayload = JDomParser::fromString(request.getPayload());
    responsePayload.put("returnValue", true);
    try {
        request.respond(responsePayload.stringify().c_str());
    } catch(exception& e) {
        PLUGIN_ERROR("Failed to respond: %s", e.what());
        return false;
    }
    PLUGIN_INFO("API-Res(%s) Sender(%s) %s",  request.getKind(), sender, responsePayload.stringify().c_str());
    return true;
}
