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

#include "handler.h"

const int Handler::APPLAUNCHPERF_LAUNCHTIMEOUT_SEC = 60;
// [I][RunningApp][setLifeStatus][c9b3edd5-f925-4442-a408-20c7428ac3ef0] Changed: com.webos.app.test.shaka-player (launching => foreground)
const string Handler::REGEX_SetLifeStatus = "\\[I\\]\\[RunningApp\\]\\[setLifeStatus\\]\\[([[:print:]]+)\\] Changed: ([[:print:]]+) \\(([[:alpha:]]+) ==> ([[:alpha:]]+)\\)";
// [I][ApplicationManager][onAPICalled][APIRequest] API(/launch) Sender(com.webos.surfacemanager)
const string Handler::REGEX_ApiLaunchCall = "\\[I\\]\\[ApplicationManager\\]\\[onAPICalled\\]\\[APIRequest\\] API\\(/launch\\) Sender\\([[:print:]]+\\)";

const string Handler::OUTKEY_TIMESTAMP = "@timestamp";
const string Handler::OUTKEY_DEVICE_ID = "device_id";
const string Handler::OUTKEY_HOSTNAME = "hostname";
const string Handler::OUTKEY_INFO_TYPE = "info_type";
const string Handler::OUTKEY_APPLAUNCH = "applaunch";
const string Handler::OUTKEY_APPLAUNCH_PERF = "applaunch_perf";
const string Handler::OUTKEY_APP_ID = "app_id";
const string Handler::OUTKEY_ELAPSED_TIME = "elapsed_time";

int initHandler(struct flb_filter_instance *instance, struct flb_config *config, void *data)
{
    return Handler::getInstance().onInit(instance, config, data);
}

int exitHandler(void *data, struct flb_config *config)
{
    return Handler::getInstance().onExit(data, config);
}

int filter(const void *data, size_t bytes, const char *tag, int tag_len, void **out_buf, size_t *out_size, struct flb_filter_instance *instance, void *context, struct flb_config *config)
{
    return Handler::getInstance().onFilter(data, bytes, tag, tag_len, out_buf, out_size, instance, context, config);
}

Handler::Handler()
    : m_filter_instance(NULL)
{
    flb_time_zero(&FLB_TIME_ZERO);
    flb_time_zero(&m_launchStartTime);
}

Handler::~Handler()
{
}

int Handler::onInit(struct flb_filter_instance *instance, struct flb_config *config, void *data)
{
    m_filter_instance = instance;
    flb_plg_info(m_filter_instance, "[%s]", __FUNCTION__);

    struct mk_list *head;
    struct flb_kv *kv;

    /* Iterate all filter parameters */
    mk_list_foreach(head, &instance->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        if (strcasecmp(kv->key, "applaunch") == 0 && strcasecmp(kv->val, "on") == 0) {
            flb_plg_info(m_filter_instance, "[%s] Applaunch is On", __FUNCTION__);
            registerRegexAndHandler(REGEX_SetLifeStatus, std::bind(&Handler::onSetLifeStatus_Applaunch, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
        }
        if (strcasecmp(kv->key, "applaunch_perf") == 0 && strcasecmp(kv->val, "on") == 0) {
            flb_plg_info(m_filter_instance, "[%s] Applaunch_perf is On", __FUNCTION__);
            registerRegexAndHandler(REGEX_ApiLaunchCall, std::bind(&Handler::onApiLaunchCall_ApplaunchPerf, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
            registerRegexAndHandler(REGEX_SetLifeStatus, std::bind(&Handler::onSetLifeStatus_ApplaunchPerf, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
        }
    }
    return 0;
}

int Handler::onExit(void *data, struct flb_config *config)
{
    flb_plg_info(m_filter_instance, "[%s]", __FUNCTION__);

    return 0;
}

int Handler::onFilter(const void *data, size_t bytes, const char *tag, int tag_len, void **out_buf, size_t *out_size, struct flb_filter_instance *instance, void *context, struct flb_config *config)
{
    struct flb_time tm;
    msgpack_object* mapObj;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_sbuffer sbuffer;
    msgpack_packer packer;
    msgpack_object* identifierObj;
    msgpack_object* messageObj;

    /* Create msgpack buffer */
    msgpack_sbuffer_init(&sbuffer);
    msgpack_packer_init(&packer, &sbuffer, msgpack_sbuffer_write);

    /* Iterate each item array and apply properties */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, (const char*)data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        /*
         * Each record is a msgpack array [timestamp, map] of the
         * timestamp and record map. We 'unpack' each record, and then re-pack
         * it with the new fields added.
         */
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            flb_plg_error(m_filter_instance, "[%s] Not array : %d", __FUNCTION__, result.data.type);
            continue;
        }
        /* unpack the array of [timestamp, map] */
        if (-1 == flb_time_pop_from_msgpack(&tm, &result, &mapObj)) {
            flb_plg_error(m_filter_instance, "[%s] Failed in flb_time_pop_from_msgpack", __FUNCTION__);
            continue;
        }
        /* map should be map type */
        if (mapObj->type != MSGPACK_OBJECT_MAP) {
            flb_plg_error(m_filter_instance, "[%s] Not map : %d", __FUNCTION__, mapObj->type);
            continue;
        }
        if (NULL == (identifierObj = findInMap(mapObj, "SYSLOG_IDENTIFIER")) || identifierObj->type != MSGPACK_OBJECT_STR) {
            continue;
        }
        if (strncmp(identifierObj->via.str.ptr, "sam", identifierObj->via.str.size) != 0) {
            continue;
        }
        if (NULL == (messageObj = findInMap(mapObj, "MESSAGE")) || messageObj->type != MSGPACK_OBJECT_STR) {
            flb_plg_error(m_filter_instance, "[%s] 'MESSAGE' not found or not string", __FUNCTION__);
            continue;
        }

        string message(messageObj->via.str.ptr, messageObj->via.str.size);
        // flb_plg_debug(m_filter_instance, "[%s] %s", __FUNCTION__, message.c_str());
        smatch match;
        for (auto it = m_regex2handlers.begin(); it != m_regex2handlers.end(); ++it) {
            if (!regex_match(message, match, regex(it->first))) {
                continue;
            }
            // flb_plg_debug(m_filter_instance, "[%s] ==> matched (%d)", __FUNCTION__,match.size());
            std::for_each(it->second.begin(), it->second.end(), [&](MessageHandler& handler){ handler(match, &result, &packer); });
        }
    }
    msgpack_unpacked_destroy(&result);

    /* link new buffers */
    *out_buf   = sbuffer.data;
    *out_size = sbuffer.size;
    return FLB_FILTER_MODIFIED;
}

void Handler::registerRegexAndHandler(const string& regex, MessageHandler handler)
{
    auto it = m_regex2handlers.find(regex);
    if (it != m_regex2handlers.end()) {
        it->second.push_back(handler);
    } else {
        m_regex2handlers[regex] = list<MessageHandler>{handler};
    }
}

void Handler::onSetLifeStatus_Applaunch(smatch& match, msgpack_unpacked* result, msgpack_packer* packer)
{
    const string& instanceId = match[1];
    const string& appId = match[2];
    const string& prevState = match[3];
    const string& currState = match[4];

    // [I][RunningApp][setLifeStatus][60c35ebf-32f8-48fb-94f0-a58b4106f8d30] Changed: com.webos.app.test.smack.web (launching => foreground)
    if (currState != "foreground")
        return;

    msgpack_pack_array(packer, 2);
    msgpack_pack_object(packer, result->data.via.array.ptr[0]); // time

    msgpack_pack_map(packer, 3);
    msgpack_pack_str(packer, OUTKEY_HOSTNAME.length());
    msgpack_pack_str_body(packer, OUTKEY_HOSTNAME.c_str(), OUTKEY_HOSTNAME.length());
    msgpack_object* hostnameObj = findInMap(&result->data.via.array.ptr[1], "_HOSTNAME");
    if (hostnameObj) {
        msgpack_pack_object(packer, *hostnameObj);
    } else {
        msgpack_pack_str(packer, 0);
        msgpack_pack_str_body(packer, "", 0);
    }

    msgpack_pack_str(packer, OUTKEY_INFO_TYPE.length());
    msgpack_pack_str_body(packer, OUTKEY_INFO_TYPE.c_str(), OUTKEY_INFO_TYPE.length());
    msgpack_pack_str(packer, strlen("applaunch"));
    msgpack_pack_str_body(packer, "applaunch", strlen("applaunch"));

    msgpack_pack_str(packer, OUTKEY_APPLAUNCH.length());
    msgpack_pack_str_body(packer, OUTKEY_APPLAUNCH.c_str(), OUTKEY_APPLAUNCH.length());
    msgpack_pack_map(packer, 1);
    msgpack_pack_str(packer, OUTKEY_APP_ID.length());
    msgpack_pack_str_body(packer, OUTKEY_APP_ID.c_str(), OUTKEY_APP_ID.length());
    msgpack_pack_str(packer, appId.length());
    msgpack_pack_str_body(packer, appId.c_str(), appId.length());
}

void Handler::onSetLifeStatus_ApplaunchPerf(smatch& match, msgpack_unpacked* result, msgpack_packer* packer)
{
    const string& instanceId = match[1];
    const string& appId = match[2];
    const string& prevState = match[3];
    const string& currState = match[4];

    // relaunching : drop m_launchStartTime
    // [I][ApplicationManager][onAPICalled][APIRequest] API(/launch) Sender(com.webos.surfacemanager)
    // [I][RunningApp][setLifeStatus][9f9842e8-4143-4256-be90-5d6b817999751] Changed: com.webos.app.home (paused => relaunching)
    // [I][RunningApp][setLifeStatus][9f9842e8-4143-4256-be90-5d6b817999751] Changed: com.webos.app.home (foreground => relaunching)
    // [I][RunningApp][setLifeStatus][9f9842e8-4143-4256-be90-5d6b817999751] Changed: com.webos.app.home (background => relaunching)
    // [I][RunningApp][setLifeStatus][9f9842e8-4143-4256-be90-5d6b817999751] Changed: com.webos.app.home (preloaded => relaunching)
    if (currState == "relaunching") {
        if (!flb_time_equal(&m_launchStartTime, &FLB_TIME_ZERO)) {
            flb_plg_debug(m_filter_instance, "[%s] Unset launchStartTime(%ld.%06ld) instanceId(%s) appId(%s) (%s ==> %s)", __FUNCTION__, m_launchStartTime.tm.tv_sec, m_launchStartTime.tm.tv_nsec/1000, instanceId.c_str(), appId.c_str(), prevState.c_str(), currState.c_str());
            flb_time_zero(&m_launchStartTime);
        }
        return;
    }

    // new launching : preserve instanceId and launchStartTime
    // [I][ApplicationManager][onAPICalled][APIRequest] API(/launch) Sender(com.webos.surfacemanager)
    // [I][RunningApp][setLifeStatus][60c35ebf-32f8-48fb-94f0-a58b4106f8d30] Changed: com.webos.app.test.smack.web (stop => splashing)
    if (prevState == "stop" && currState == "splashing") {
        if (flb_time_equal(&m_launchStartTime, &FLB_TIME_ZERO)) {
            flb_plg_error(m_filter_instance, "[%s] launchStartTime not found (new launching) : %s", __FUNCTION__, match.str().c_str());
            return;
        }
        m_instanceId2launchStartTime.emplace(instanceId, m_launchStartTime);
        flb_plg_debug(m_filter_instance, "[%s] Unset launchStartTime(%ld.%06ld) instanceId(%s) appId(%s) (%s ==> %s)", __FUNCTION__, m_launchStartTime.tm.tv_sec, m_launchStartTime.tm.tv_nsec/1000, instanceId.c_str(), appId.c_str(), prevState.c_str(), currState.c_str());
        flb_plg_debug(m_filter_instance, "[%s]  Push launchStartTime(%ld.%06ld) instanceId(%s) appId(%s) (%s ==> %s)", __FUNCTION__, m_launchStartTime.tm.tv_sec, m_launchStartTime.tm.tv_nsec/1000, instanceId.c_str(), appId.c_str(), prevState.c_str(), currState.c_str());
        flb_time_zero(&m_launchStartTime);
        return;
    }

    // new launching, but it ended without completion
    // [I][RunningApp][setLifeStatus][12150505-5e39-4e4e-82ac-934bc0d8e91c0] Changed: com.webos.app.mediagallery (launching => stop)
    // [I][RunningApp][setLifeStatus][12150505-5e39-4e4e-82ac-934bc0d8e91c0] Changed: com.webos.app.mediagallery (launching => background)
    if (currState == "stop" || currState == "background") {
        auto it = m_instanceId2launchStartTime.find(instanceId);
        if (it != m_instanceId2launchStartTime.end()) {
            m_instanceId2launchStartTime.erase(it);
            flb_plg_debug(m_filter_instance, "[%s] Erase launchStartTime(%ld.%06ld) instanceId(%s) appId(%s) (%s ==> %s)", __FUNCTION__, it->second.tm.tv_sec, it->second.tm.tv_nsec/1000, instanceId.c_str(), appId.c_str(), prevState.c_str(), currState.c_str());
        }
        return;
    }

    // new launching, and completed
    // [I][ApplicationManager][onAPICalled][APIRequest] API(/launch) Sender(com.webos.surfacemanager)
    // [I][RunningApp][setLifeStatus][60c35ebf-32f8-48fb-94f0-a58b4106f8d30] Changed: com.webos.app.test.smack.web (stop => splashing)
    // [I][RunningApp][setLifeStatus][60c35ebf-32f8-48fb-94f0-a58b4106f8d30] Changed: com.webos.app.test.smack.web (splashing => splashed)
    // [I][RunningApp][setLifeStatus][60c35ebf-32f8-48fb-94f0-a58b4106f8d30] Changed: com.webos.app.test.smack.web (splashed => launching)
    // [I][RunningApp][setLifeStatus][60c35ebf-32f8-48fb-94f0-a58b4106f8d30] Changed: com.webos.app.test.smack.web (launching => foreground)
    if (prevState != "launching" || currState != "foreground") {
        return;
    }
    auto it = m_instanceId2launchStartTime.find(instanceId);
    if (it == m_instanceId2launchStartTime.end()) {
        flb_plg_error(m_filter_instance, "[%s] instanceId not found (foreground) : %s", __FUNCTION__, match.str().c_str());
        return;
    }
    m_instanceId2launchStartTime.erase(it);
    flb_plg_debug(m_filter_instance, "[%s] Erase launchStartTime(%ld.%06ld) instanceId(%s) appId(%s) (%s ==> %s)", __FUNCTION__, it->second.tm.tv_sec, it->second.tm.tv_nsec/1000, instanceId.c_str(), appId.c_str(), prevState.c_str(), currState.c_str());

    msgpack_pack_array(packer, 2);
    msgpack_pack_object(packer, result->data.via.array.ptr[0]); // time

    msgpack_pack_map(packer, 3);
    msgpack_pack_str(packer, OUTKEY_HOSTNAME.length());
    msgpack_pack_str_body(packer, OUTKEY_HOSTNAME.c_str(), OUTKEY_HOSTNAME.length());
    msgpack_object* hostnameObj = findInMap(&result->data.via.array.ptr[1], "_HOSTNAME");
    if (hostnameObj) {
        msgpack_pack_object(packer, *hostnameObj);
    } else {
        msgpack_pack_str(packer, 0);
        msgpack_pack_str_body(packer, "", 0);
    }

    msgpack_pack_str(packer, OUTKEY_INFO_TYPE.length());
    msgpack_pack_str_body(packer, OUTKEY_INFO_TYPE.c_str(), OUTKEY_INFO_TYPE.length());
    msgpack_pack_str(packer, strlen("applaunch_perf"));
    msgpack_pack_str_body(packer, "applaunch_perf", strlen("applaunch_perf"));

    msgpack_pack_str(packer, OUTKEY_APPLAUNCH_PERF.length());
    msgpack_pack_str_body(packer, OUTKEY_APPLAUNCH_PERF.c_str(), OUTKEY_APPLAUNCH_PERF.length());
    msgpack_pack_map(packer, 2);
    msgpack_pack_str(packer, OUTKEY_APP_ID.length());
    msgpack_pack_str_body(packer, OUTKEY_APP_ID.c_str(), OUTKEY_APP_ID.length());
    msgpack_pack_str(packer, appId.length());
    msgpack_pack_str_body(packer, appId.c_str(), appId.length());

    msgpack_object *map;
    flb_time curr, diff;
    flb_time_pop_from_msgpack(&curr, result, &map);
    flb_time_diff(&curr, &it->second, &diff);
    msgpack_pack_str(packer, OUTKEY_ELAPSED_TIME.length());
    msgpack_pack_str_body(packer, OUTKEY_ELAPSED_TIME.c_str(), OUTKEY_ELAPSED_TIME.length());
    msgpack_pack_double(packer, flb_time_to_double(&diff));
}

void Handler::onApiLaunchCall_ApplaunchPerf(smatch& match, msgpack_unpacked* result, msgpack_packer* packer)
{
    msgpack_object* map;
    flb_time_pop_from_msgpack(&m_launchStartTime, result, &map);
    flb_plg_debug(m_filter_instance, "[%s]   Set launchStartTime(%ld.%06ld)", __FUNCTION__, m_launchStartTime.tm.tv_sec, m_launchStartTime.tm.tv_nsec/1000);

    // Delete entries that have passed 1 minutes after launching apps.
    flb_time diff;
    for (auto it = m_instanceId2launchStartTime.begin(); it != m_instanceId2launchStartTime.end(); ) {
        flb_time_diff(&m_launchStartTime, &it->second, &diff);
        if (diff.tm.tv_sec < APPLAUNCHPERF_LAUNCHTIMEOUT_SEC) {
            ++it;
            continue;
        }
        flb_plg_info(m_filter_instance, "[%s] Timeout launchStartTime(%ld.%06ld) instanceId(%s) diff(%ld.%06ld)", __FUNCTION__, it->second.tm.tv_sec, it->second.tm.tv_nsec/1000, it->first.c_str(), diff.tm.tv_sec, diff.tm.tv_nsec/1000);
        it = m_instanceId2launchStartTime.erase(it);
    }
}

msgpack_object* Handler::findInMap(msgpack_object* map, const char* keystr)
{
    const char *key;
    uint32_t keylen;
    for (uint32_t idx = 0; idx < map->via.map.size; idx++) {
        if (MSGPACK_OBJECT_STR != map->via.map.ptr[idx].key.type) {
            continue;
        }
        key = map->via.map.ptr[idx].key.via.str.ptr;
        keylen = map->via.map.ptr[idx].key.via.str.size;
        if (strlen(keystr) == keylen && strncmp(key, keystr, keylen) == 0) {
            return &map->via.map.ptr[idx].val;
        }
    }
    return NULL;
}

string Handler::toDebugString(msgpack_object* map)
{
    string str = "{\n";
    for (uint32_t idx = 0; idx < map->via.map.size; idx++) {
        string key;
        if (MSGPACK_OBJECT_STR == map->via.map.ptr[idx].key.type) {
            key = string(map->via.map.ptr[idx].key.via.str.ptr, map->via.map.ptr[idx].key.via.str.size);
        } else if (MSGPACK_OBJECT_BIN == map->via.map.ptr[idx].key.type) {
            key = string(map->via.map.ptr[idx].key.via.bin.ptr, map->via.map.ptr[idx].key.via.bin.size);
        }
        string val;
        if (MSGPACK_OBJECT_STR == map->via.map.ptr[idx].val.type) {
            val = string(map->via.map.ptr[idx].val.via.str.ptr, map->via.map.ptr[idx].val.via.str.size);
        } else if (MSGPACK_OBJECT_BIN == map->via.map.ptr[idx].val.type) {
            val = string(map->via.map.ptr[idx].val.via.bin.ptr, map->via.map.ptr[idx].val.via.bin.size);
        }
        str += "    " + key + ": " + val + "\n";
    }
    str += "}";
    return str;
}
