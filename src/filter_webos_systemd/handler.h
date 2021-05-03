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

#ifdef __cplusplus
extern "C" {
#endif

#include <fluent-bit.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_time.h>

int initHandler(struct flb_filter_instance *instance, struct flb_config *config, void *data);
int exitHandler(void *data, struct flb_config *config);
int filter(const void *data, size_t bytes, const char *tag, int tag_len, void **out_buf, size_t *out_size, struct flb_filter_instance *instance, void *context, struct flb_config *config);

using namespace std;

typedef std::function<void(smatch& match, msgpack_unpacked* result, msgpack_packer* packer)> MessageHandler;

class Handler {
public:
    static Handler &getInstance()
    {
        static Handler instance;
        return instance;
    }

    virtual ~Handler();

    int onInit(struct flb_filter_instance *instance, struct flb_config *config, void *data);
    int onExit(void *data, struct flb_config *confi);
    int onFilter(const void *data, size_t bytes, const char *tag, int tag_len, void **out_buf, size_t *out_size, struct flb_filter_instance *instance, void *context, struct flb_config *config);

private:
    static msgpack_object* findInMap(msgpack_object* map, const char* keystr);
    static string toDebugString(msgpack_object* map);

    Handler();

    void registerRegexAndHandler(const string& regex, MessageHandler handler);

    void onSetLifeStatus_Applaunch(smatch& match, msgpack_unpacked* result, msgpack_packer* packer);
    void onSetLifeStatus_ApplaunchPerf(smatch& match, msgpack_unpacked* result, msgpack_packer* packer);
    void onApiLaunchCall_ApplaunchPerf(smatch& match, msgpack_unpacked* result, msgpack_packer* packer);

    static const int APPLAUNCHPERF_LAUNCHTIMEOUT_SEC;
    static const string REGEX_SetLifeStatus;
    static const string REGEX_ApiLaunchCall;

    static const string OUTKEY_TIMESTAMP;
    static const string OUTKEY_DEVICE_ID;
    static const string OUTKEY_HOSTNAME;
    static const string OUTKEY_INFO_TYPE;
    static const string OUTKEY_APPLAUNCH;
    static const string OUTKEY_APPLAUNCH_PERF;
    static const string OUTKEY_APP_ID;
    static const string OUTKEY_ELAPSED_TIME;

    flb_filter_instance* m_filter_instance;

    map<string, list<MessageHandler>> m_regex2handlers;

    // Use as an initial value (constant) for time
    flb_time FLB_TIME_ZERO;
    // The launch start time of an app should be obtained from 'API(/launch)'.
    // But, the message does not contains appId.
    // So, we take the launched appId from immediately following 'setLifeStatus'.
    // Then, (if the app is not re-launched,) we preserve the instanceId and start time in map.
    flb_time m_launchStartTime;
    map<string, flb_time> m_instanceId2launchStartTime;

};

#ifdef __cplusplus
}
#endif

#endif
