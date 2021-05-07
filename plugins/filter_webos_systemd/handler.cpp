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

#include "PerfRecord.h"
#include "PerfRecordList.h"
#include "util/LinuxUtil.h"
#include "util/MSGPackUtil.h"
#include "util/Time.h"

const int Handler::APPLAUNCHPERF_TIMEOUT_SEC = 60;
// [I][RunningApp][setLifeStatus][c9b3edd5-f925-4442-a408-20c7428ac3ef0] Changed: com.webos.app.test.shaka-player (launching => foreground)
const string Handler::REGEX_SetLifeStatus = "\\[I\\]\\[RunningApp\\]\\[setLifeStatus\\]\\[([[:print:]]+)\\] Changed: ([[:print:]]+) \\(([[:alpha:]]+) ==> ([[:alpha:]]+)\\)";
// [I][ApplicationManager][onAPICalled][APIRequest] API(/launch) Sender(com.webos.surfacemanager)
const string Handler::REGEX_ApiLaunchCall = "\\[I\\]\\[ApplicationManager\\]\\[onAPICalled\\]\\[APIRequest\\] API\\(/launch\\) Sender\\([[:print:]]+\\)";

extern "C" int initHandler(struct flb_filter_instance *instance, struct flb_config *config, void *data)
{
    return Handler::getInstance().onInit(instance, config, data);
}

extern "C" int exitHandler(void *data, struct flb_config *config)
{
    return Handler::getInstance().onExit(data, config);
}

extern "C" int filter(const void *data, size_t bytes, const char *tag, int tag_len, void **out_buf, size_t *out_size, struct flb_filter_instance *instance, void *context, struct flb_config *config)
{
    return Handler::getInstance().onFilter(data, bytes, tag, tag_len, out_buf, out_size, instance, context, config);
}

Handler::Handler()
    : m_filter_instance(NULL)
    , m_appLaunchPerfRecords(APPLAUNCHPERF_TIMEOUT_SEC)
{
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
            registerRegexAndHandler(REGEX_SetLifeStatus, std::bind(&Handler::onAppLaunch, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
        }
        if (strcasecmp(kv->key, "applaunch_perf") == 0 && strcasecmp(kv->val, "on") == 0) {
            flb_plg_info(m_filter_instance, "[%s] Applaunch_perf is On", __FUNCTION__);
            registerRegexAndHandler(REGEX_ApiLaunchCall, std::bind(&Handler::onAppLaunchPerf_begin, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
            registerRegexAndHandler(REGEX_SetLifeStatus, std::bind(&Handler::onAppLaunchPerf_end, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
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

        if (!MSGPackUtil::getValue(mapObj, "SYSLOG_IDENTIFIER", syslogIdentifier) || syslogIdentifier != "sam") {
            continue;
        }
        if (!MSGPackUtil::getValue(mapObj, "MESSAGE", message)) {
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
    *out_buf = sbuffer.data;
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

bool Handler::packCommonMsg(msgpack_unpacked* result, flb_time* timestamp, msgpack_packer* packer, size_t mapSize)
{
    msgpack_pack_array(packer, 2);
    msgpack_pack_object(packer, result->data.via.array.ptr[0]); // time
    msgpack_pack_map(packer, mapSize);

    MSGPackUtil::packKeyVal(packer, "timestamp", Time::toISO8601(&timestamp->tm));
    MSGPackUtil::packMap(packer, "deviceInfo", 4);
    MSGPackUtil::packKeyVal(packer, "deviceId", m_deviceId);
    MSGPackUtil::packKeyVal(packer, "deviceName", m_deviceName);
    MSGPackUtil::packKeyVal(packer, "webosName", m_webosName);
    MSGPackUtil::packKeyVal(packer, "webosBuildId", m_webosBuildId);
    return true;
}

void Handler::onAppLaunch(smatch& match, msgpack_unpacked* result, msgpack_packer* packer)
{
    const string& instanceId = match[1];
    const string& appId = match[2];
    const string& prevState = match[3];
    const string& currState = match[4];

    msgpack_object* map;
    flb_time timestamp;
    flb_time_pop_from_msgpack(&timestamp, result, &map);

    // [I][RunningApp][setLifeStatus][60c35ebf-32f8-48fb-94f0-a58b4106f8d30] Changed: com.webos.app.test.smack.web (launching => foreground)
    if (currState != "foreground")
        return;
    if (!packCommonMsg(result, &timestamp, packer, 4))
        return;

    string uid;
    string accountId;
    try {
        if (MSGPackUtil::getValue(&result->data.via.array.ptr[1], "_UID", uid) && !uid.empty()) {
            accountId = LinuxUtil::getUsername(stoul(uid, nullptr, 10));
        }
    } catch (exception& ex) {
        flb_plg_warn(m_filter_instance, "[%s] Cannot convert uid %s: %s", __FUNCTION__, uid.c_str(), ex.what());
    }
    MSGPackUtil::packKeyVal(packer, "type", "appLaunch");
    MSGPackUtil::packMap(packer, "appLaunch", 2);
    MSGPackUtil::packKeyVal(packer, "accountId", accountId);
    MSGPackUtil::packKeyVal(packer, "appId", appId);
}

void Handler::onAppLaunchPerf_begin(smatch& match, msgpack_unpacked* result, msgpack_packer* packer)
{
    msgpack_object* map;
    flb_time timestamp;
    flb_time_pop_from_msgpack(&timestamp, result, &map);
    flb_plg_debug(m_filter_instance, "[%s] Timestamp(%ld.%03ld)", __FUNCTION__, timestamp.tm.tv_sec, timestamp.tm.tv_nsec/(1000*1000));

    shared_ptr<PerfRecord> perfRecord = make_shared<PerfRecord>();
    perfRecord->addTimestamp(PerfRecord::STATE_BEGIN, timestamp);
    m_appLaunchPerfRecords.add(perfRecord);

    size_t beforeNoContextItemSize = m_appLaunchPerfRecords.getNoContextItems().size();
    size_t beforeContextItemSize = m_appLaunchPerfRecords.getContext2itemMap().size();
    m_appLaunchPerfRecords.removeExpired(&timestamp);
    size_t afterNoContextItemSize = m_appLaunchPerfRecords.getNoContextItems().size();
    size_t afterContextItemSize = m_appLaunchPerfRecords.getContext2itemMap().size();
    flb_plg_debug(m_filter_instance, "[%s] Expired(%ld, %ld), Remain(%ld, %ld)", __FUNCTION__, (beforeNoContextItemSize-afterNoContextItemSize), (beforeContextItemSize-afterContextItemSize), afterNoContextItemSize, afterContextItemSize);
}

void Handler::onAppLaunchPerf_end(smatch& match, msgpack_unpacked* result, msgpack_packer* packer)
{
    const string& instanceId = match[1];
    const string& appId = match[2];
    const string& prevState = match[3];
    const string& currState = match[4];

    msgpack_object *map;
    flb_time timestamp, total;
    flb_time_pop_from_msgpack(&timestamp, result, &map);
    flb_plg_debug(m_filter_instance, "[%s] Timestamp(%ld.%03ld) %s (%s => %s) %s", __FUNCTION__, timestamp.tm.tv_sec, timestamp.tm.tv_nsec/(1000*1000), instanceId.c_str(), prevState.c_str(), currState.c_str(), appId.c_str());

    // [I][RunningApp][setLifeStatus][60c35ebf-32f8-48fb-94f0-a58b4106f8d30] Changed: com.webos.app.test.smack.web (stop => splashing)
    if (prevState == "stop" && currState == "splashing") {
        shared_ptr<PerfRecord> perfRecord = m_appLaunchPerfRecords.get(instanceId);
        if (!perfRecord) {
            flb_plg_error(m_filter_instance, "[%s] Timestamp(%ld.%03ld) %s Not found", __FUNCTION__, timestamp.tm.tv_sec, timestamp.tm.tv_nsec/(1000*1000), instanceId.c_str());
            return;
        }
        // There is no need to add a timestamp to perfItem.
        // This is just a step of mapping the launchStartTime and context.
        perfRecord->setContext(instanceId);
    }

    // [I][RunningApp][setLifeStatus][60c35ebf-32f8-48fb-94f0-a58b4106f8d30] Changed: com.webos.app.test.smack.web (launching => foreground)
    if (prevState != "launching" || currState != "foreground") {
        return;
    }
    shared_ptr<PerfRecord> perfRecord = m_appLaunchPerfRecords.get(instanceId);
    if (!perfRecord) {
        flb_plg_error(m_filter_instance, "[%s] Timestamp(%ld.%03ld) %s Not found", __FUNCTION__, timestamp.tm.tv_sec, timestamp.tm.tv_nsec/(1000*1000), instanceId.c_str());
        return;
    }
    perfRecord->addTimestamp(PerfRecord::STATE_END, timestamp);
    perfRecord->getTotalTime(&total);
    m_appLaunchPerfRecords.remove(instanceId);

    if (!packCommonMsg(result, &timestamp, packer, 4))
        return;

    string uid;
    string accountId;
    try {
        if (MSGPackUtil::getValue(&result->data.via.array.ptr[1], "_UID", uid) && !uid.empty()) {
            accountId = LinuxUtil::getUsername(stoul(uid, nullptr, 10));
        }
    } catch (exception& ex) {
        flb_plg_warn(m_filter_instance, "[%s] Cannot convert uid %s: %s", __FUNCTION__, uid.c_str(), ex.what());
    }
    MSGPackUtil::packKeyVal(packer, "type", "appLaunchPerf");
    MSGPackUtil::packMap(packer, "appLaunchPerf", 3);
    MSGPackUtil::packKeyVal(packer, "accountId", accountId);
    MSGPackUtil::packKeyVal(packer, "appId", appId);
    MSGPackUtil::packKeyVal(packer, "totalTime", flb_time_to_double(&total));
}
