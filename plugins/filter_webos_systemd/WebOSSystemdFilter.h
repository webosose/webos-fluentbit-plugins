// Copyright (c) 2021-2022 LG Electronics, Inc.
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

#ifndef WEBOS_SYSTEMD_FILTER_H_
#define WEBOS_SYSTEMD_FILTER_H_

#include <functional>
#include <list>
#include <map>
#include <memory>
#include <regex>
#include <string>
#include <pbnjson.hpp>

#include "FluentBit.h"

#include "interface/IClassName.h"
#include "interface/ISingleton.h"

using namespace pbnjson;
using namespace std;

class WebOSSystemdFilter : public IClassName,
                           public ISingleton<WebOSSystemdFilter> {
friend class ISingleton<WebOSSystemdFilter>;
public:
    virtual ~WebOSSystemdFilter();

    int onInit(struct flb_filter_instance *instance, struct flb_config *config, void *data);
    int onExit(void *context, struct flb_config *confi);
    int onFilter(const void *data, size_t bytes, const char *tag, int tag_len, void **out_buf, size_t *out_size, struct flb_filter_instance *instance, void *context, struct flb_config *config);

private:
    typedef std::function<void(msgpack_unpacked* result, msgpack_packer* packer)> SyslogIdentifierHandler;

    WebOSSystemdFilter();

    bool packCommonMsg(msgpack_unpacked* result, flb_time* timestamp, msgpack_packer* packer, size_t mapSize);
    void handlePowerOn(msgpack_unpacked* result, msgpack_packer* packer);
    void handleAppExecution(msgpack_unpacked* result, msgpack_packer* packer);

    static const string PATH_RESPAWNED;

    bool m_isRespawned;
    // Used to exclude the past time journald logs, when respawned.
    struct timespec m_respawnedTime;
    JValue m_deviceInfo;
    // For each module, register handlers : sam, bootd, pamlogin, ..
    map<string, SyslogIdentifierHandler> m_syslogIdentifier2handler;
    bool m_isPowerOnDone;
    map<string, struct flb_time> m_instanceId2timestamp;
};

#endif
