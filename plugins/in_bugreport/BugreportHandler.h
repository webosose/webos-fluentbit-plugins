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

#ifndef BUGREPORTHANDLER_H_
#define BUGREPORTHANDLER_H_

#include <string>

#include "BugreportConfigManager.h"
#include "BugreportScreenshotManager.h"
#include "FluentBit.h"
#include "bus/LunaHandle.h"
#include "external/rpa_queue.h"
#include "interface/IClassName.h"
#include "interface/ISingleton.h"
#include "util/ErrCode.h"

using namespace std;

class BugreportHandler : public LunaHandle,
                         public ISingleton<BugreportHandler> {
friend class ISingleton<BugreportHandler>;
public:
    virtual ~BugreportHandler();

    int onInit(struct flb_input_instance *in, struct flb_config *config, void *data);
    int onExit(void *in_context, struct flb_config *config);
    int onCollect(struct flb_input_instance *ins, struct flb_config *config, void *in_context);

private:
    static bool onDeviceListChanged(LSHandle *sh, LSMessage *reply, void *ctx);
    static int findKeyboardFd();
    static gboolean onKeyboardEvent(GIOChannel *channel, GIOCondition condition, gpointer data);
    static bool onCreateToast(LSHandle *sh, LSMessage *message, void *ctx);
    static bool onLaunchBugreportApp(LSHandle *sh, LSMessage *message, void *ctx);
    static bool onProcessMethod(LSHandle *sh, LSMessage *msg, void *ctx);

    BugreportHandler();

    bool onRegisterServerStatus(bool isConnected);
    void createToast(const string& message);
    void launchBugreportApp();
    bool pushToRpaQueue(JValue payload);

    ErrCode getConfig(JValue& requestPayload, JValue& responsePayload);
    ErrCode setConfig(JValue& requestPayload, JValue& responsePayload);
    ErrCode createBug(JValue& requestPayload, JValue& responsePayload);
    ErrCode processDeprecatedMethod(JValue& = Null, JValue& = Null);
    ErrCode processF9(JValue& = Null , JValue& = Null);
    ErrCode processF10(JValue& = Null , JValue& = Null);
    ErrCode processF11(JValue& = Null , JValue& = Null);
    ErrCode processF12(JValue& = Null , JValue& = Null);

    static const LSMethod METHOD_TABLE[];
    static JValue Null;

    struct flb_input_instance *m_inputInstance;
    rpa_queue_t *m_queue;
    ServerStatus m_serverStatus;
    LSMessageToken m_deviceListSubscriptionToken;
    int m_keyboardFd;
    bool m_isAltPressed;
    bool m_isCtrlPressed;

    BugreportConfigManager m_configManager;
    BugreportScreenshotManager m_screenshotManager;
};

#endif
