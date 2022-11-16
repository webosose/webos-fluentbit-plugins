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

    // To prevent too many calls in case of failure
    inline bool isTimeSyncJustTried();
    inline bool isTimeSyncDone();

    void pushEvent(pair<flb_time, JValue> event);
    void calcTimeCorrection();
    bool packCommonMsg(msgpack_unpacked* result, flb_time* timestamp, msgpack_packer* packer, size_t mapSize);
    void handlePowerOn(msgpack_unpacked* result, msgpack_packer* packer);
    void handleAppExecution(msgpack_unpacked* result, msgpack_packer* packer);
    void handleAppUsage(msgpack_unpacked* result, msgpack_packer* packer);
    void handleTimeSync(msgpack_unpacked* result, msgpack_packer* packer);
    void handleErrorLog(msgpack_unpacked* result, msgpack_packer* packer, const string& priority);

    static const string PATH_RESPAWNED;

    bool m_isRespawned;
    // Used to exclude the past time journald logs, when respawned.
    struct timespec m_respawnedTime;
    JValue m_deviceInfo;
    // For each module, register handlers : sam, bootd, pamlogin, ..
    map<string, SyslogIdentifierHandler> m_syslogIdentifier2handler;
    // powerOn
    bool m_isPowerOnDone;
    // appExecution
    map<string, struct flb_time> m_instanceId2timestamp;
    // time sync and corection
    // ex) m_monotimeBeforeSync = 20
    //     m_realtimeBeforeSync = 2001-04-01
    //       monotimeAfterSync  = 140
    //       realtimeAfterSync  = 2022-11-02
    //     m_realtimeDiff       =   21-07-01
    //     m_minPrevRealtime    = 2022-11-02 - 20
    //     m_maxPrevRealtime    = 2022-11-02 + (140 - 20)
    // if a logged realtime < m_lastPrevRealtime
    //     converted = a logged realtime + m_realtimeDiff - m_monotimeDiff
    struct timespec m_monotimeBeforeSync;
    struct timespec m_realtimeBeforeSync;
    struct timespec m_realtimeDiff;
    struct timespec m_monotimeDiff;
    struct timespec m_minPrevRealtime;
    struct timespec m_maxPrevRealtime;
    list<pair<flb_time, JValue>> m_pendings;
    time_t m_lscallLastTime;
    bool m_isTimeSyncDone;
};

#endif
