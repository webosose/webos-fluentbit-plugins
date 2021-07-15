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

#include "Handler.h"

#include <glib.h>
#include <pwd.h>

#include "PerfRecord.h"
#include "PerfRecordList.h"
#include "util/File.h"
#include "util/LinuxUtil.h"
#include "util/Logger.h"
#include "util/MSGPackUtil.h"
#include "util/Time.h"

const string Handler::PATH_RESPAWNED = "/tmp/fluentbit-respawned";
const int Handler::APPLAUNCHPERF_TIMEOUT_SEC = 60;
// [I][RunningApp][setLifeStatus][c9b3edd5-f925-4442-a408-20c7428ac3ef0] Changed: com.webos.app.test.shaka-player (launching => foreground)
const string Handler::REGEX_SetLifeStatus = "^\\[I\\]\\[RunningApp\\]\\[setLifeStatus\\]\\[([[:print:]]+)\\] Changed: ([[:print:]]+) \\(([[:alpha:]]+) ==> ([[:alpha:]]+)\\)";
// [I][ApplicationManager][onAPICalled][APIRequest] API(/launch) Sender(com.webos.surfacemanager)
const string Handler::REGEX_ApiLaunchCall = "^\\[I\\]\\[ApplicationManager\\]\\[onAPICalled\\]\\[APIRequest\\] API\\(/launch\\) Sender\\([[:print:]]+\\)";
// [I][RuntimeInfo][initialize] DisplayId(-1) DeviceType() IsInContainer(false)
// [I][RuntimeInfo][initialize] DisplayId(1) DeviceType(RSE) IsInContainer(true)
const string Handler::REGEX_RuntimeInfo = "^\\[I\\]\\[RuntimeInfo\\]\\[initialize\\] DisplayId\\(([[:graph:]]+)\\) DeviceType\\([[:graph:]]*\\) IsInContainer\\([[:graph:]]*\\)";

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
    : m_isRespawned(false),
      m_appLaunchPerfRecords(APPLAUNCHPERF_TIMEOUT_SEC),
      m_isBootTimePerfDone(false)
{
    setClassName("Handler");
    m_deviceInfo = pbnjson::Object();
}

Handler::~Handler()
{
}

int Handler::onInit(struct flb_filter_instance *instance, struct flb_config *config, void *data)
{
    // Check isRespawned
    m_isRespawned = File::isFile(PATH_RESPAWNED);
    if (!m_isRespawned) {
        File::createFile(PATH_RESPAWNED);
    } else {
        if (-1 == clock_gettime(CLOCK_REALTIME, &m_respawnedTime)) {
            PLUGIN_ERROR("Failed to clock_gettime : %s", strerror(errno));
            m_respawnedTime = { 0, 0 };
        }
        PLUGIN_INFO("Respawned Timestamp(%ld.%03ld)", m_respawnedTime.tv_sec, m_respawnedTime.tv_nsec/(1000*1000));
    }

    // Get device info
    string deviceId, deviceName, webosName, webosBuildId;
    gchar *output;
    GError *error = NULL;
    if (!g_spawn_command_line_sync("nyx-cmd DeviceInfo query nduid device_name", &output, NULL, NULL, &error)) {
        PLUGIN_ERROR("nyx-cmd error: %s", error->message);
        g_error_free(error);
        return -1;
    }
    std::istringstream outStream(output);
    (void)std::getline(outStream, deviceId, '\n');
    (void)std::getline(outStream, deviceName, '\n');
    g_free(output);
    if (!g_spawn_command_line_sync("nyx-cmd OSInfo query webos_name webos_build_id", &output, NULL, NULL, &error)) {
        PLUGIN_ERROR("nyx-cmd error: %s", error->message);
        g_error_free(error);
        return -1;
    }
    outStream.str(output);
    (void)std::getline(outStream, webosName, '\n');
    (void)std::getline(outStream, webosBuildId, '\n');
    g_free(output);
    if (deviceId.empty() || deviceName.empty() || webosName.empty() || webosBuildId.empty()) {
        PLUGIN_ERROR("At least one of deviceId, deviceName, webosName, webosBuildId is empty");
        g_error_free(error);
        return -1;
    }
    m_deviceInfo.put("deviceId", deviceId);
    m_deviceInfo.put("deviceName", deviceName);
    m_deviceInfo.put("webosName", webosName);
    m_deviceInfo.put("webosBuildId", webosBuildId);
    PLUGIN_INFO("deviceId : %s", deviceId.c_str());
    PLUGIN_INFO("deviceName : %s", deviceName.c_str());
    PLUGIN_INFO("webosName : %s", webosName.c_str());
    PLUGIN_INFO("webosBuildId : %s", webosBuildId.c_str());

    bool isAppLaunchOn = true, isAppLaunchPerfOn = true, isLoginLogoutOn = true, isCrashOn = true, isBootTimePerfOn = true;
    struct mk_list *head;
    struct flb_kv *kv;
    /* Iterate all filter parameters */
    mk_list_foreach(head, &instance->properties) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        if (strcasecmp(kv->key, "applaunch") == 0 && strcasecmp(kv->val, "off") == 0)
            isAppLaunchOn = false;
        if (strcasecmp(kv->key, "applaunch_perf") == 0 && strcasecmp(kv->val, "off") == 0)
            isAppLaunchPerfOn = false;
        if (strcasecmp(kv->key, "login_logout") == 0 && strcasecmp(kv->val, "off") == 0)
            isLoginLogoutOn = false;
        if (strcasecmp(kv->key, "crash") == 0 && strcasecmp(kv->val, "off") == 0)
            isCrashOn = false;
        if (strcasecmp(kv->key, "boottime_perf") == 0 && strcasecmp(kv->val, "off") == 0)
            isBootTimePerfOn = false;
    }
    if (isAppLaunchOn) {
        PLUGIN_INFO("Applaunch is On");
        m_syslogIdentifier2handler["sam"] = std::bind(&Handler::handleSam, this, std::placeholders::_1, std::placeholders::_2);
        registerRegexAndHandler(REGEX_SetLifeStatus, std::bind(&Handler::handleSamAppLaunch, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
    }
    if (isAppLaunchPerfOn) {
        PLUGIN_INFO("Applaunch_Perf is On");
        m_syslogIdentifier2handler["sam"] = std::bind(&Handler::handleSam, this, std::placeholders::_1, std::placeholders::_2);
        registerRegexAndHandler(REGEX_ApiLaunchCall, std::bind(&Handler::handleSamAppLaunchPerf_begin, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
        registerRegexAndHandler(REGEX_SetLifeStatus, std::bind(&Handler::handleSamAppLaunchPerf_end, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
    }
    if (isLoginLogoutOn) {
        PLUGIN_INFO("Login/Logout is On");
        m_syslogIdentifier2handler["pamlogin"] = std::bind(&Handler::handlePamlogin, this, std::placeholders::_1, std::placeholders::_2);
    }
    if (isCrashOn) {
        PLUGIN_INFO("Crash is On");
        m_syslogIdentifier2handler["systemd-coredump"] = std::bind(&Handler::handleSystemdCoredump, this, std::placeholders::_1, std::placeholders::_2);
    }
    if (isBootTimePerfOn) {
        PLUGIN_INFO("Boottime_Perf is On");
        m_syslogIdentifier2handler["sam"] = std::bind(&Handler::handleSam, this, std::placeholders::_1, std::placeholders::_2);
        registerRegexAndHandler(REGEX_RuntimeInfo, std::bind(&Handler::handleSamBootTimePerf_begin, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
        registerRegexAndHandler(REGEX_SetLifeStatus, std::bind(&Handler::handleSamBootTimePerf_end, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
    }
    return 0;
}

int Handler::onExit(void *context, struct flb_config *config)
{
    PLUGIN_INFO();

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
            PLUGIN_WARN("Not array : %d", result.data.type);
            continue;
        }
        /* unpack the array of [timestamp, map] */
        if (-1 == flb_time_pop_from_msgpack(&tm, &result, &mapObj)) {
            PLUGIN_WARN("Failed in flb_time_pop_from_msgpack");
            continue;
        }
        if (m_isRespawned && tm.tm < m_respawnedTime) {
            continue;
        }
        /* map should be map type */
        if (mapObj->type != MSGPACK_OBJECT_MAP) {
            PLUGIN_WARN("Not map : %d", mapObj->type);
            continue;
        }

        if (!MSGPackUtil::getValue(mapObj, "SYSLOG_IDENTIFIER", syslogIdentifier)) {
            continue;
        }
        auto it = m_syslogIdentifier2handler.find(syslogIdentifier);
        if (it == m_syslogIdentifier2handler.end()) {
            continue;
        }
        SyslogIdentifierHandler& handler = it->second;
        handler(&result, &packer);
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

    MSGPackUtil::putValue(packer, "timestamp", Time::toISO8601(&timestamp->tm));
    MSGPackUtil::putValue(packer, "deviceInfo", m_deviceInfo);
    return true;
}

void Handler::handleSamAppLaunch(smatch& match, msgpack_unpacked* result, msgpack_packer* packer)
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
        PLUGIN_WARN("Cannot convert uid %s: %s", uid.c_str(), ex.what());
    }
    MSGPackUtil::putValue(packer, "type", "appLaunch");
    JValue appLaunch = Object();
    appLaunch.put("accountId", accountId);
    appLaunch.put("appId", appId);
    MSGPackUtil::putValue(packer, "appLaunch", appLaunch);
    PLUGIN_INFO("[appLaunch] %s", appLaunch.stringify().c_str());
}

void Handler::handleSamAppLaunchPerf_begin(smatch& match, msgpack_unpacked* result, msgpack_packer* packer)
{
    msgpack_object* map;
    flb_time timestamp;
    flb_time_pop_from_msgpack(&timestamp, result, &map);

    m_appLaunchPerfRecords.removeExpired(&timestamp);
    PLUGIN_DEBUG("Remove expired : Remain(%ld, %ld)", m_appLaunchPerfRecords.getNoContextItems().size(), m_appLaunchPerfRecords.getContext2itemMap().size());

    shared_ptr<PerfRecord> perfRecord = make_shared<PerfRecord>();
    perfRecord->addTimestamp("begin", timestamp);
    m_appLaunchPerfRecords.add(perfRecord);
    PLUGIN_DEBUG("Timestamp(%ld.%03ld)", timestamp.tm.tv_sec, timestamp.tm.tv_nsec/(1000*1000));
}

void Handler::handleSamAppLaunchPerf_end(smatch& match, msgpack_unpacked* result, msgpack_packer* packer)
{
    const string& instanceId = match[1];
    const string& appId = match[2];
    const string& prevState = match[3];
    const string& currState = match[4];

    msgpack_object *map;
    flb_time timestamp, total;
    flb_time_pop_from_msgpack(&timestamp, result, &map);

    // [I][RunningApp][setLifeStatus][60c35ebf-32f8-48fb-94f0-a58b4106f8d30] Changed: com.webos.app.test.smack.web (stop => splashing)
    if (prevState == "stop" && currState == "splashing") {
        PLUGIN_DEBUG("Timestamp(%ld.%03ld) %s (%s => %s) %s", timestamp.tm.tv_sec, timestamp.tm.tv_nsec/(1000*1000), instanceId.c_str(), prevState.c_str(), currState.c_str(), appId.c_str());
        shared_ptr<PerfRecord> perfRecord = m_appLaunchPerfRecords.get(instanceId);
        if (!perfRecord) {
            PLUGIN_ERROR("Timestamp(%ld.%03ld) Not found : %s", timestamp.tm.tv_sec, timestamp.tm.tv_nsec/(1000*1000), string(match[0]).c_str());
            return;
        }
        // There is no need to add a timestamp to perfItem.
        // This is just a step of mapping the launchStartTime and context.
        perfRecord->setContext(instanceId);
        return;
    }

    // [I][RunningApp][setLifeStatus][60c35ebf-32f8-48fb-94f0-a58b4106f8d30] Changed: com.webos.app.test.smack.web (launching => foreground)
    if (prevState != "launching" || currState != "foreground") {
        return;
    }
    PLUGIN_DEBUG("Timestamp(%ld.%03ld) %s (%s => %s) %s", timestamp.tm.tv_sec, timestamp.tm.tv_nsec/(1000*1000), instanceId.c_str(), prevState.c_str(), currState.c_str(), appId.c_str());
    shared_ptr<PerfRecord> perfRecord = m_appLaunchPerfRecords.get(instanceId);
    if (!perfRecord) {
        PLUGIN_ERROR("Timestamp(%ld.%03ld) Not found : %s", timestamp.tm.tv_sec, timestamp.tm.tv_nsec/(1000*1000), string(match[0]).c_str());
        return;
    }
    perfRecord->addTimestamp("end", timestamp);
    if (!perfRecord->getElapsedTime("", "", &total)) {
        PLUGIN_ERROR("Failed to get elapsed time");
        return;
    }
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
        PLUGIN_WARN("Cannot convert uid %s: %s", uid.c_str(), ex.what());
    }
    MSGPackUtil::putValue(packer, "type", "appLaunchPerf");
    JValue appLaunchPerf = Object();
    appLaunchPerf.put("accountId", accountId);
    appLaunchPerf.put("appId", appId);
    appLaunchPerf.put("totalTimeMs", (int)(flb_time_to_double(&total)*1000+0.5)); // round-off
    MSGPackUtil::putValue(packer, "appLaunchPerf", appLaunchPerf);
    PLUGIN_INFO("[appLaunchPerf] %s", appLaunchPerf.stringify().c_str());
}

void Handler::handleSamBootTimePerf_begin(smatch& match, msgpack_unpacked* result, msgpack_packer* packer)
{
    if (m_isBootTimePerfDone || m_isRespawned)
        return;
    string pid;
    if (!MSGPackUtil::getValue(&result->data.via.array.ptr[1], "_PID", pid))
        return;

    const string& displayId = match[1];
    // count the number of displays
    m_displayId2bootdone[displayId] = make_pair(pid, false);
    PLUGIN_DEBUG("displayId(%s)", displayId.c_str());
}

void Handler::handleSamBootTimePerf_end(smatch& match, msgpack_unpacked* result, msgpack_packer* packer)
{
    if (m_isBootTimePerfDone || m_isRespawned)
        return;
    if ("foreground" != match[4])
        return;
    string pid;
    if (!MSGPackUtil::getValue(&result->data.via.array.ptr[1], "_PID", pid))
        return;

    bool isBootdoneOnAllDisplays = true;
    msgpack_object *map;
    flb_time loggedRealtime;
    flb_time_pop_from_msgpack(&loggedRealtime, result, &map);

    for (auto& kv : m_displayId2bootdone) {
        if (kv.second.first == pid) {
            kv.second.second = true;
        }
        if (!kv.second.second) {
            isBootdoneOnAllDisplays = false;
        }
    }
    if (!isBootdoneOnAllDisplays) {
        return;
    }

    JValue bootTimePerf = Object();
    flb_time currentRealtime, currentMonotonic;
    flb_time elapsedTimeSinceLogged;
    flb_time monotonicAtLogged;
    if (-1 == clock_gettime(CLOCK_REALTIME, &currentRealtime.tm)) {
        PLUGIN_ERROR("Failed to clock_gettime : %s", strerror(errno));
        goto Done;
    }
    if (-1 == clock_gettime(CLOCK_MONOTONIC, &currentMonotonic.tm)) {
        PLUGIN_ERROR("Failed to clock_gettime : %s", strerror(errno));
        goto Done;
    }
    // Analyzing the logs, the kernel starts with 0 monotonic time.
    // So, the monotonic time at the point of logged is considered as the boot time.
    flb_time_diff(&currentRealtime, &loggedRealtime, &elapsedTimeSinceLogged);
    flb_time_diff(&currentMonotonic, &elapsedTimeSinceLogged, &monotonicAtLogged);

    if (!packCommonMsg(result, &loggedRealtime, packer, 4))
        goto Done;
    MSGPackUtil::putValue(packer, "type", "bootTimePerf");
    bootTimePerf.put("totalTimeMs", (int)(flb_time_to_double(&monotonicAtLogged)*1000+0.5)); // round-off
    MSGPackUtil::putValue(packer, "bootTimePerf", bootTimePerf);
    PLUGIN_INFO("[bootTimePerf] %s", bootTimePerf.stringify().c_str());

Done:
    m_isBootTimePerfDone = true;
}

void Handler::handleSam(msgpack_unpacked* result, msgpack_packer* packer)
{
    string message;
    if (!MSGPackUtil::getValue(&result->data.via.array.ptr[1], "MESSAGE", message))
        return;
    smatch match;
    for (auto it = m_regex2handlers.begin(); it != m_regex2handlers.end(); ++it) {
        if (!regex_match(message, match, regex(it->first))) {
            continue;
        }
        std::for_each(it->second.begin(), it->second.end(), [&](MessageHandler& handler){ handler(match, result, packer); });
    }
}

void Handler::handlePamlogin(msgpack_unpacked* result, msgpack_packer* packer)
{
    flb_time timestamp;
    string sourceTime;
    string message;
    if (!MSGPackUtil::getValue(&result->data.via.array.ptr[1], "_SOURCE_REALTIME_TIMESTAMP", sourceTime))
        return;
    if (!MSGPackUtil::getValue(&result->data.via.array.ptr[1], "MESSAGE", message))
        return;
    timestamp.tm.tv_sec = stoi(sourceTime.substr(0, sourceTime.length()-6));
    timestamp.tm.tv_nsec = stol(sourceTime.substr(sourceTime.length()-6)) * 1000;

    // pam_unix(pamlogin:session): session closed for user driver0
    // pam_unix(pamlogin:session): session opened for user guest0 by (uid=0)
    smatch match;
    if (!regex_search(message, match, regex("^pam_unix\\(pamlogin:session\\): session (opened|closed) for user ([[:graph:]]+)")))
        return;
    if (!packCommonMsg(result, &timestamp, packer, 4))
        return;
    string typeStr = ("opened" == match[1]) ? "login" : "logout";
    JValue typeObj = Object();
    typeObj.put("accountId", string(match[2]));
    MSGPackUtil::putValue(packer, "type", typeStr);
    MSGPackUtil::putValue(packer, typeStr, typeObj);
    PLUGIN_INFO("[%s] %s", typeStr.c_str(), typeObj.stringify().c_str());
}

void Handler::handleSystemdCoredump(msgpack_unpacked* result, msgpack_packer* packer)
{
    flb_time timestamp;
    int signalNo;
    string sourceTime;
    string signal;
    string exe;
    if (!MSGPackUtil::getValue(&result->data.via.array.ptr[1], "_SOURCE_REALTIME_TIMESTAMP", sourceTime))
        return;
    if (!MSGPackUtil::getValue(&result->data.via.array.ptr[1], "COREDUMP_SIGNAL", signal))
        return;
    if (!MSGPackUtil::getValue(&result->data.via.array.ptr[1], "COREDUMP_EXE", exe))
        return;
    timestamp.tm.tv_sec = stoi(sourceTime.substr(0, sourceTime.length()-6));
    timestamp.tm.tv_nsec = stol(sourceTime.substr(sourceTime.length()-6)) * 1000;
    signalNo = stoi(signal);

    if (!packCommonMsg(result, &timestamp, packer, 4))
        return;
    MSGPackUtil::putValue(packer, "type", "crash");
    JValue crash = Object();
    crash.put("exe", exe);
    crash.put("signal", signalNo);
    MSGPackUtil::putValue(packer, "crash", crash);
    PLUGIN_INFO("[crash] %s", crash.stringify().c_str());
}
