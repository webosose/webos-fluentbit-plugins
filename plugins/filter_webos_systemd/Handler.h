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

#ifndef HANDLER_H_
#define HANDLER_H_

#include <functional>
#include <list>
#include <map>
#include <memory>
#include <regex>
#include <string>
#include <pbnjson.hpp>

#ifdef __cplusplus
extern "C" {
#endif

#include <fluent-bit.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_time.h>

#ifdef __cplusplus
}
#endif

#include "PerfRecordList.h"
#include "interface/ISingleton.h"

using namespace pbnjson;
using namespace std;

class Handler : public ISingleton<Handler> {
friend class ISingleton<Handler>;
public:
    virtual ~Handler();

    int onInit(struct flb_filter_instance *instance, struct flb_config *config, void *data);
    int onExit(void *context, struct flb_config *confi);
    int onFilter(const void *data, size_t bytes, const char *tag, int tag_len, void **out_buf, size_t *out_size, struct flb_filter_instance *instance, void *context, struct flb_config *config);

private:
    typedef std::function<void(smatch& match, msgpack_unpacked* result, msgpack_packer* packer)> MessageHandler;
    typedef std::function<void(msgpack_unpacked* result, msgpack_packer* packer)> SyslogIdentifierHandler;

    Handler();

    void registerRegexAndHandler(const string& regex, MessageHandler handler);
    bool packCommonMsg(msgpack_unpacked* result, flb_time* timestamp, msgpack_packer* packer, size_t mapSize);

    void handleSamAppLaunch(smatch& match, msgpack_unpacked* result, msgpack_packer* packer);
    void handleSamAppLaunchPerf_begin(smatch& match, msgpack_unpacked* result, msgpack_packer* packer);
    void handleSamAppLaunchPerf_end(smatch& match, msgpack_unpacked* result, msgpack_packer* packer);

    void handleSam(msgpack_unpacked* result, msgpack_packer* packer);
    void handlePamlogin(msgpack_unpacked* result, msgpack_packer* packer);
    void handleSystemdCoredump(msgpack_unpacked* result, msgpack_packer* packer);

    static const string PATH_RESPAWNED;
    static const int APPLAUNCHPERF_TIMEOUT_SEC;
    static const string REGEX_SetLifeStatus;
    static const string REGEX_ApiLaunchCall;

    flb_filter_instance* m_filter_instance;

    bool m_isRespawned;
    struct timespec m_respawnedTime;
    JValue m_deviceInfo;

    map<string, SyslogIdentifierHandler> m_syslogIdentifier2handler;
    map<string, list<MessageHandler>> m_regex2handlers;

    PerfRecordList m_appLaunchPerfRecords;

};

#endif
