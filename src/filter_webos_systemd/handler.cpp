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

#include <glib.h>
#include <pwd.h>

const int Handler::APPLAUNCHPERF_LAUNCHTIMEOUT_SEC = 60;
// [I][RunningApp][setLifeStatus][c9b3edd5-f925-4442-a408-20c7428ac3ef0] Changed: com.webos.app.test.shaka-player (launching => foreground)
const string Handler::REGEX_SetLifeStatus = "\\[I\\]\\[RunningApp\\]\\[setLifeStatus\\]\\[([[:print:]]+)\\] Changed: ([[:print:]]+) \\(([[:alpha:]]+) ==> ([[:alpha:]]+)\\)";
// [I][ApplicationManager][onAPICalled][APIRequest] API(/launch) Sender(com.webos.surfacemanager)
const string Handler::REGEX_ApiLaunchCall = "\\[I\\]\\[ApplicationManager\\]\\[onAPICalled\\]\\[APIRequest\\] API\\(/launch\\) Sender\\([[:print:]]+\\)";

const string Handler::OUTKEY_TIMESTAMP = "timestamp";
const string Handler::OUTKEY_DEVICE_INFO = "deviceInfo";
const string Handler::OUTKEY_DEVICE_ID = "deviceId";
const string Handler::OUTKEY_DEVICE_NAME = "deviceName";
const string Handler::OUTKEY_WEBOS_NAME = "webosName";
const string Handler::OUTKEY_WEBOS_BUILD_ID = "webosBuildId";
const string Handler::OUTKEY_INFO_TYPE = "type";
const string Handler::OUTKEY_APPLAUNCH = "appLaunch";
const string Handler::OUTKEY_APPLAUNCH_PERF = "appLaunchPerf";
const string Handler::OUTKEY_ACCOUNT_ID = "accountId";
const string Handler::OUTKEY_APP_ID = "appId";
const string Handler::OUTKEY_ELAPSED_TIME = "elapsedTime";

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
    // Used in log flb_plg_XXX
    m_filter_instance = instance;

    // Get device info
    gchar *output;
    GError *error = NULL;
    if (!g_spawn_command_line_sync("nyx-cmd DeviceInfo query nduid device_name", &output, NULL, NULL, &error)) {
        flb_plg_error(m_filter_instance, "[%s] nyx-cmd error: %s", __FUNCTION__, error->message);
        g_error_free(error);
        return -1;
    }
    std::istringstream outStream(output);
    (void)std::getline(outStream, m_deviceId, '\n');
    (void)std::getline(outStream, m_deviceName, '\n');
    g_free(output);
    if (!g_spawn_command_line_sync("nyx-cmd OSInfo query webos_name webos_build_id", &output, NULL, NULL, &error)) {
        flb_plg_error(m_filter_instance, "[%s] nyx-cmd error: %s", __FUNCTION__, error->message);
        g_error_free(error);
        return -1;
    }
    outStream.str(output);
    (void)std::getline(outStream, m_webosName, '\n');
    (void)std::getline(outStream, m_webosBuildId, '\n');
    g_free(output);
    if (m_deviceId.empty() || m_deviceName.empty() || m_webosName.empty() || m_webosBuildId.empty()) {
        flb_plg_error(m_filter_instance, "[%s] At least one of deviceId, deviceName, webosName, webosBuildId is empty", __FUNCTION__);
        g_error_free(error);
        return -1;
    }
    flb_plg_info(m_filter_instance, "[%s] deviceId : %s", __FUNCTION__, m_deviceId.c_str());
    flb_plg_info(m_filter_instance, "[%s] deviceName : %s", __FUNCTION__, m_deviceName.c_str());
    flb_plg_info(m_filter_instance, "[%s] webosName : %s", __FUNCTION__, m_webosName.c_str());
    flb_plg_info(m_filter_instance, "[%s] webosBuildId : %s", __FUNCTION__, m_webosBuildId.c_str());

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

int Handler::onExit(void *context, struct flb_config *config)
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
    string syslogIdentifier;
    string message;

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
            flb_plg_warn(m_filter_instance, "[%s] Not array : %d", __FUNCTION__, result.data.type);
            continue;
        }
        /* unpack the array of [timestamp, map] */
        if (-1 == flb_time_pop_from_msgpack(&tm, &result, &mapObj)) {
            flb_plg_warn(m_filter_instance, "[%s] Failed in flb_time_pop_from_msgpack", __FUNCTION__);
            continue;
        }
        /* map should be map type */
        if (mapObj->type != MSGPACK_OBJECT_MAP) {
            flb_plg_warn(m_filter_instance, "[%s] Not map : %d", __FUNCTION__, mapObj->type);
            continue;
        }

        if (!getValue(mapObj, "SYSLOG_IDENTIFIER", syslogIdentifier) || syslogIdentifier != "sam") {
            continue;
        }
        if (!getValue(mapObj, "MESSAGE", message)) {
            flb_plg_warn(m_filter_instance, "[%s] 'MESSAGE' not found or not string", __FUNCTION__);
            continue;
        }
        smatch match;
        for (auto it = m_regex2handlers.begin(); it != m_regex2handlers.end(); ++it) {
            if (!regex_match(message, match, regex(it->first))) {
                continue;
            }
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

bool Handler::packCommonMsg(msgpack_unpacked* result, msgpack_packer* packer)
{
    flb_time tm;
    msgpack_object* mapObj;
    if (-1 == flb_time_pop_from_msgpack(&tm, result, &mapObj)) {
        return false;
    }

    msgpack_pack_array(packer, 2);
    msgpack_pack_object(packer, result->data.via.array.ptr[0]); // time
    msgpack_pack_map(packer, 4);

    msgpack_pack_str(packer, OUTKEY_TIMESTAMP.length());
    msgpack_pack_str_body(packer, OUTKEY_TIMESTAMP.c_str(), OUTKEY_TIMESTAMP.length());
    const string& timestamp = convertUtcString(&tm);
    msgpack_pack_str(packer, timestamp.length());
    msgpack_pack_str_body(packer, timestamp.c_str(), timestamp.length());

    msgpack_pack_str(packer, OUTKEY_DEVICE_INFO.length());
    msgpack_pack_str_body(packer, OUTKEY_DEVICE_INFO.c_str(), OUTKEY_DEVICE_INFO.length());
    msgpack_pack_map(packer, 4);

    msgpack_pack_str(packer, OUTKEY_DEVICE_ID.length());
    msgpack_pack_str_body(packer, OUTKEY_DEVICE_ID.c_str(), OUTKEY_DEVICE_ID.length());
    msgpack_pack_str(packer, m_deviceId.length());
    msgpack_pack_str_body(packer, m_deviceId.c_str(), m_deviceId.length());

    msgpack_pack_str(packer, OUTKEY_DEVICE_NAME.length());
    msgpack_pack_str_body(packer, OUTKEY_DEVICE_NAME.c_str(), OUTKEY_DEVICE_NAME.length());
    msgpack_pack_str(packer, m_deviceName.length());
    msgpack_pack_str_body(packer, m_deviceName.c_str(), m_deviceName.length());

    msgpack_pack_str(packer, OUTKEY_WEBOS_NAME.length());
    msgpack_pack_str_body(packer, OUTKEY_WEBOS_NAME.c_str(), OUTKEY_WEBOS_NAME.length());
    msgpack_pack_str(packer, m_webosName.length());
    msgpack_pack_str_body(packer, m_webosName.c_str(), m_webosName.length());

    msgpack_pack_str(packer, OUTKEY_WEBOS_BUILD_ID.length());
    msgpack_pack_str_body(packer, OUTKEY_WEBOS_BUILD_ID.c_str(), OUTKEY_WEBOS_BUILD_ID.length());
    msgpack_pack_str(packer, m_webosBuildId.length());
    msgpack_pack_str_body(packer, m_webosBuildId.c_str(), m_webosBuildId.length());

    return true;
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
    if (!packCommonMsg(result, packer))
        return;

    msgpack_pack_str(packer, OUTKEY_INFO_TYPE.length());
    msgpack_pack_str_body(packer, OUTKEY_INFO_TYPE.c_str(), OUTKEY_INFO_TYPE.length());
    msgpack_pack_str(packer, OUTKEY_APPLAUNCH.length());
    msgpack_pack_str_body(packer, OUTKEY_APPLAUNCH.c_str(), OUTKEY_APPLAUNCH.length());

    msgpack_pack_str(packer, OUTKEY_APPLAUNCH.length());
    msgpack_pack_str_body(packer, OUTKEY_APPLAUNCH.c_str(), OUTKEY_APPLAUNCH.length());
    msgpack_pack_map(packer, 2);

    msgpack_pack_str(packer, OUTKEY_ACCOUNT_ID.length());
    msgpack_pack_str_body(packer, OUTKEY_ACCOUNT_ID.c_str(), OUTKEY_ACCOUNT_ID.length());
    string uid;
    string accountId;
    if (getValue(&result->data.via.array.ptr[1], "_UID", uid) && !uid.empty()) {
        try {
            accountId = convertUidToName(stoul(uid, nullptr, 10));
        } catch (exception& ex) {
            flb_plg_warn(m_filter_instance, "[%s] Cannot convert uid %s: %s", __FUNCTION__, uid.c_str(), ex.what());
        }
    }
    msgpack_pack_str(packer, accountId.length());
    msgpack_pack_str_body(packer, accountId.c_str(), accountId.length());

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
    // [I][RunningApp][setLifeStatus][9f9842e8-4143-4256-be90-5d6b817999751] Changed: com.webos.app.home (foreground => relaunching)
    if (currState == "relaunching") {
        if (!flb_time_equal(&m_launchStartTime, &FLB_TIME_ZERO)) {
            flb_plg_debug(m_filter_instance, "[%s] Unset launchStartTime(%ld.%03ld) instanceId(%s) appId(%s) (%s ==> %s)", __FUNCTION__, m_launchStartTime.tm.tv_sec, m_launchStartTime.tm.tv_nsec/(1000*1000), instanceId.c_str(), appId.c_str(), prevState.c_str(), currState.c_str());
            flb_time_zero(&m_launchStartTime);
        }
        return;
    }

    // new launching : preserve instanceId and launchStartTime
    // [I][RunningApp][setLifeStatus][60c35ebf-32f8-48fb-94f0-a58b4106f8d30] Changed: com.webos.app.test.smack.web (stop => splashing)
    if (prevState == "stop" && currState == "splashing") {
        if (flb_time_equal(&m_launchStartTime, &FLB_TIME_ZERO)) {
            flb_plg_error(m_filter_instance, "[%s] launchStartTime not found (new launching) : %s", __FUNCTION__, match.str().c_str());
            return;
        }
        m_instanceId2launchStartTime.emplace(instanceId, m_launchStartTime);
        flb_plg_debug(m_filter_instance, "[%s] Unset launchStartTime(%ld.%03ld) instanceId(%s) appId(%s) (%s ==> %s)", __FUNCTION__, m_launchStartTime.tm.tv_sec, m_launchStartTime.tm.tv_nsec/(1000*1000), instanceId.c_str(), appId.c_str(), prevState.c_str(), currState.c_str());
        flb_plg_debug(m_filter_instance, "[%s]  Push launchStartTime(%ld.%03ld) instanceId(%s) appId(%s) (%s ==> %s)", __FUNCTION__, m_launchStartTime.tm.tv_sec, m_launchStartTime.tm.tv_nsec/(1000*1000), instanceId.c_str(), appId.c_str(), prevState.c_str(), currState.c_str());
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
            flb_plg_debug(m_filter_instance, "[%s] Erase launchStartTime(%ld.%03ld) instanceId(%s) appId(%s) (%s ==> %s)", __FUNCTION__, it->second.tm.tv_sec, it->second.tm.tv_nsec/(1000*1000), instanceId.c_str(), appId.c_str(), prevState.c_str(), currState.c_str());
        }
        return;
    }

    // new launching, and completed
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
    flb_plg_debug(m_filter_instance, "[%s] Erase launchStartTime(%ld.%03ld) instanceId(%s) appId(%s) (%s ==> %s)", __FUNCTION__, it->second.tm.tv_sec, it->second.tm.tv_nsec/(1000*1000), instanceId.c_str(), appId.c_str(), prevState.c_str(), currState.c_str());

    if (!packCommonMsg(result, packer))
        return;

    msgpack_pack_str(packer, OUTKEY_INFO_TYPE.length());
    msgpack_pack_str_body(packer, OUTKEY_INFO_TYPE.c_str(), OUTKEY_INFO_TYPE.length());
    msgpack_pack_str(packer, OUTKEY_APPLAUNCH_PERF.length());
    msgpack_pack_str_body(packer, OUTKEY_APPLAUNCH_PERF.c_str(), OUTKEY_APPLAUNCH_PERF.length());

    msgpack_pack_str(packer, OUTKEY_APPLAUNCH_PERF.length());
    msgpack_pack_str_body(packer, OUTKEY_APPLAUNCH_PERF.c_str(), OUTKEY_APPLAUNCH_PERF.length());
    msgpack_pack_map(packer, 3);

    msgpack_pack_str(packer, OUTKEY_ACCOUNT_ID.length());
    msgpack_pack_str_body(packer, OUTKEY_ACCOUNT_ID.c_str(), OUTKEY_ACCOUNT_ID.length());
    string uid;
    string accountId;
    if (getValue(&result->data.via.array.ptr[1], "_UID", uid) && !uid.empty()) {
        try {
            accountId = convertUidToName(stoul(uid, nullptr, 10));
        } catch (exception& ex) {
            flb_plg_warn(m_filter_instance, "[%s] Cannot convert uid %s: %s", __FUNCTION__, uid.c_str(), ex.what());
        }
    }
    msgpack_pack_str(packer, accountId.length());
    msgpack_pack_str_body(packer, accountId.c_str(), accountId.length());

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
    flb_plg_debug(m_filter_instance, "[%s]   Set launchStartTime(%ld.%03ld)", __FUNCTION__, m_launchStartTime.tm.tv_sec, m_launchStartTime.tm.tv_nsec/(1000*1000));

    // Delete entries that have passed 1 minutes after launching apps.
    flb_time diff;
    for (auto it = m_instanceId2launchStartTime.begin(); it != m_instanceId2launchStartTime.end(); ) {
        flb_time_diff(&m_launchStartTime, &it->second, &diff);
        if (diff.tm.tv_sec < APPLAUNCHPERF_LAUNCHTIMEOUT_SEC) {
            ++it;
            continue;
        }
        flb_plg_info(m_filter_instance, "[%s] Timeout launchStartTime(%ld.%03ld) instanceId(%s) diff(%ld.%03ld)", __FUNCTION__, it->second.tm.tv_sec, it->second.tm.tv_nsec/(1000*1000), it->first.c_str(), diff.tm.tv_sec, diff.tm.tv_nsec/(1000*1000));
        it = m_instanceId2launchStartTime.erase(it);
    }
}

msgpack_object* Handler::getValueObj(msgpack_object* map, const string& keystr)
{
    const char *key;
    uint32_t keylen;
    for (uint32_t idx = 0; idx < map->via.map.size; idx++) {
        if (MSGPACK_OBJECT_STR != map->via.map.ptr[idx].key.type) {
            continue;
        }
        key = map->via.map.ptr[idx].key.via.str.ptr;
        keylen = map->via.map.ptr[idx].key.via.str.size;
        if (keystr.length() == keylen && strncmp(key, keystr.c_str(), keylen) == 0) {
            return &map->via.map.ptr[idx].val;
        }
    }
    return NULL;
}

bool Handler::getValue(msgpack_object* map, const string& key, string& value)
{
    msgpack_object* obj = getValueObj(map, key.c_str());
    if (!obj) {
        return false;
    }
    if (MSGPACK_OBJECT_STR != obj->type) {
        return false;
    }
    value = string(obj->via.str.ptr, obj->via.str.size);
    return true;
}

string Handler::convertUidToName(unsigned int uid)
{
    struct passwd* pwd = getpwuid(uid);
    if (!pwd) {
        return "";
    }
    return pwd->pw_name;
}

string Handler::convertUtcString(flb_time* time)
{
    static size_t BUFSIZE = 25;
    char buff[BUFSIZE];
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    if (!gmtime_r(&time->tm.tv_sec, &tm)) {
        return "";
    }
    size_t size = strftime(buff, sizeof(buff), "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(buff+size, BUFSIZE-size, ".%03ldZ", time->tm.tv_nsec/(1000*1000));
    return buff;
}
