// Copyright (c) 2021-2023 LG Electronics, Inc.
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

#include "WebOSSystemdFilter.h"

#include <glib.h>
#include <pwd.h>

#include "util/File.h"
#include "util/JValueUtil.h"
#include "util/LinuxUtil.h"
#include "util/Logger.h"
#include "util/MSGPackUtil.h"
#include "util/Time.h"

#define EPOCHTIME_20220101      1640995200

#define QUEUE_MAX_ENTRIES       500

const string WebOSSystemdFilter::PATH_RESPAWNED = "/tmp/fluentbit-respawned";

extern "C" int initWebOSSystemdFilter(struct flb_filter_instance *instance, struct flb_config *config, void *data)
{
    return WebOSSystemdFilter::getInstance().onInit(instance, config, data);
}

extern "C" int exitWebOSSystemdFilter(void *data, struct flb_config *config)
{
    return WebOSSystemdFilter::getInstance().onExit(data, config);
}

extern "C" int filterWebOSSystemd(const void *data, size_t bytes, const char *tag, int tag_len, void **out_buf, size_t *out_size, struct flb_filter_instance *instance, void *context, struct flb_config *config)
{
    return WebOSSystemdFilter::getInstance().onFilter(data, bytes, tag, tag_len, out_buf, out_size, instance, context, config);
}

WebOSSystemdFilter::WebOSSystemdFilter()
    : m_isRespawned(false)
    , m_isPowerOnDone(false)
    , m_monotimeBeforeSync({0, 0})
    , m_realtimeBeforeSync({0, 0})
    , m_realtimeDiff({0, 0})
    , m_monotimeDiff({0, 0})
    , m_minPrevRealtime({0, 0})
    , m_maxPrevRealtime({0, 0})
    , m_isTimeSyncDone(false)
{
    setClassName("WebOSSystemdFilter");
    m_respawnedTime = { 0, 0 };
    m_deviceInfo = pbnjson::Object();
}

WebOSSystemdFilter::~WebOSSystemdFilter()
{
}

int WebOSSystemdFilter::onInit(struct flb_filter_instance *instance, struct flb_config *config, void *data)
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
    if (!g_spawn_command_line_sync("nyx-cmd DeviceInfo query wired_addr device_name", &output, NULL, NULL, &error)) {
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

    if (-1 == clock_gettime(CLOCK_MONOTONIC, &m_monotimeBeforeSync))
        PLUGIN_ERROR("Failed to clock_gettime (MONOTIME) : %s", strerror(errno));
    PLUGIN_INFO("MonotimeBeforeSync : %10lld.%09ld", m_monotimeBeforeSync.tv_sec, m_monotimeBeforeSync.tv_nsec);
    if (-1 == clock_gettime(CLOCK_REALTIME, &m_realtimeBeforeSync))
        PLUGIN_ERROR("Failed to clock_gettime (REALTIME) : %s", strerror(errno));
    PLUGIN_INFO("RealtimeBeforeSync : %10lld.%09ld", m_realtimeBeforeSync.tv_sec, m_realtimeBeforeSync.tv_nsec);

    m_syslogIdentifier2handler["LunaSysService"] = std::bind(&WebOSSystemdFilter::handlePowerOn, this, std::placeholders::_1, std::placeholders::_2);
    m_syslogIdentifier2handler["sam"] = std::bind(&WebOSSystemdFilter::handleAppExecution, this, std::placeholders::_1, std::placeholders::_2);
    m_syslogIdentifier2handler["WebAppMgr"] = std::bind(&WebOSSystemdFilter::handleAppUsage, this, std::placeholders::_1, std::placeholders::_2);
    return 0;
}

int WebOSSystemdFilter::onExit(void *context, struct flb_config *config)
{
    PLUGIN_INFO();

    return 0;
}

int WebOSSystemdFilter::onFilter(const void *data, size_t bytes, const char *tag, int tag_len, void **out_buf, size_t *out_size, struct flb_filter_instance *instance, void *context, struct flb_config *config)
{
    struct flb_time tm;
    msgpack_object* mapObj;
    size_t off = 0;
    msgpack_unpacked result;
    msgpack_sbuffer sbuffer;
    msgpack_packer packer;
    string syslogIdentifier;
    string priority;

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
        // Since the Read_From_Tail option of in_systemd is set to false by default,
        // whenever fluentbit starts (or restarts), all journal logs are entered from begining.
        // In this situation, the following conditions prevent duplicate data.
        if (m_isRespawned && tm.tm < m_respawnedTime) {
            continue;
        }
        /* map should be map type */
        if (mapObj->type != MSGPACK_OBJECT_MAP) {
            PLUGIN_WARN("Not map : %d", mapObj->type);
            continue;
        }
        // 0: Emergency, 1: Alert, 2: Critical, 3: Error, ..
        if (MSGPackUtil::getValue(mapObj, "PRIORITY", priority)) {
            if (priority <= "3") {
                handleErrorLog(&result, &packer, priority);
                // Return here, because all info except 'error log' is extracted from info-level log.
                continue;
            }
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

bool WebOSSystemdFilter::isTimeSyncDone()
{
    return m_isTimeSyncDone;
}

void WebOSSystemdFilter::pushEvent(pair<flb_time, JValue> event)
{
    while (m_pendings.size() >= QUEUE_MAX_ENTRIES)
        m_pendings.pop_front();
    m_pendings.emplace_back(event);
}

void WebOSSystemdFilter::processPendings(msgpack_unpacked* result, msgpack_packer* packer)
{
    struct timespec realtimeAfterSync;
    struct timespec monotimeAfterSync;
    struct timespec realtimeDiff;
    struct timespec monotimeDiff;

    if (-1 == clock_gettime(CLOCK_REALTIME, &realtimeAfterSync)) {
        PLUGIN_ERROR("Failed to clock_gettime (REALTIME) : %s", strerror(errno));
        return;
    }
    if (-1 == clock_gettime(CLOCK_MONOTONIC, &monotimeAfterSync)) {
        PLUGIN_ERROR("Failed to clock_gettime (MONOTIME) : %s", strerror(errno));
        return;
    }
    PLUGIN_INFO("MonotimeBeforeSync : %10lld.%09ld", m_monotimeBeforeSync.tv_sec, m_monotimeBeforeSync.tv_nsec);
    PLUGIN_INFO("RealtimeBeforeSync : %10lld.%09ld", m_realtimeBeforeSync.tv_sec, m_realtimeBeforeSync.tv_nsec);
    PLUGIN_INFO("RealtimeAfterSync  : %10lld.%09ld", realtimeAfterSync.tv_sec, realtimeAfterSync.tv_nsec);
    PLUGIN_INFO("MonotimeAfterSync  : %10lld.%09ld", monotimeAfterSync.tv_sec, monotimeAfterSync.tv_nsec);
    m_realtimeDiff = realtimeAfterSync - m_realtimeBeforeSync;
    m_monotimeDiff = monotimeAfterSync - m_monotimeBeforeSync;
    PLUGIN_INFO("RealtimeDiff       : %10lld.%09ld", m_realtimeDiff.tv_sec, m_realtimeDiff.tv_nsec);
    PLUGIN_INFO("MonotimeDiff       : %10lld.%09ld", m_monotimeDiff.tv_sec, m_monotimeDiff.tv_nsec);
    // The range of Timestamp before NTP sync.
    m_minPrevRealtime = m_realtimeBeforeSync - m_monotimeBeforeSync;
    m_maxPrevRealtime = m_realtimeBeforeSync + m_monotimeDiff;
    PLUGIN_INFO("MinPrevRealtime    : %10lld.%09ld", m_minPrevRealtime.tv_sec, m_minPrevRealtime.tv_nsec);
    PLUGIN_INFO("MaxPrevRealtime    : %10lld.%09ld", m_maxPrevRealtime.tv_sec, m_maxPrevRealtime.tv_nsec);
    PLUGIN_INFO("TimeDiffCalculated.");

    if (m_instanceId2timestamp.size() > 0) {
        for (auto& it : m_instanceId2timestamp) {
            PLUGIN_INFO("Foreground (%10ld.%03d) %s Checking timestamp..", it.second.tm.tv_sec, it.second.tm.tv_nsec/(1000*1000), it.first.c_str());
            if (m_minPrevRealtime < it.second.tm && it.second.tm < m_maxPrevRealtime) {
                it.second.tm = it.second.tm + m_realtimeDiff - m_monotimeDiff;
                PLUGIN_INFO("Foreground (%10ld.%03d) %s Updated!", it.second.tm.tv_sec, it.second.tm.tv_nsec/(1000*1000), it.first.c_str());
            }
        }
    }

    if (m_pendings.size() > 0) {
        PLUGIN_INFO("Process pendings..");
        flb_time ts;
        for (int idx = 0; !m_pendings.empty(); idx++) {
            pair<flb_time, JValue>& item = m_pendings.front();
            if (m_minPrevRealtime < item.first.tm && item.first.tm < m_maxPrevRealtime) {
                ts.tm = item.first.tm + m_realtimeDiff - m_monotimeDiff;
                PLUGIN_INFO("(%03d) [%s] %10lld.%03ld <= %10lld.%03ld", idx, Time::toISO8601(&ts.tm).c_str(), ts.tm.tv_sec, ts.tm.tv_nsec/(1000*1000), item.first.tm.tv_sec, item.first.tm.tv_nsec/(1000*1000));
            } else {
                ts.tm = item.first.tm;
                PLUGIN_INFO("(%03d) [%s] %10lld.%03ld", idx, Time::toISO8601(&ts.tm).c_str(), ts.tm.tv_sec, ts.tm.tv_nsec/(1000*1000));
            }
            (void)packCommonMsg(result, &ts, packer, 2 + item.second.objectSize());
            for (JValue::KeyValue kv : item.second.children()) {
                if (kv.second.isString()) {
                    const string& k = kv.first.asString();
                    const string& v = kv.second.asString();
                    MSGPackUtil::putValue(packer, k, v);
                    PLUGIN_INFO("  %s: %s", k.c_str(), v.c_str());
                    continue;
                }
                // object extra
                if (kv.first.asString() != "extra") {
                    continue;
                }
                // object extra : only for appExecution
                if (kv.second.hasKey("_beginMs")) {
                    int64_t beginMs = kv.second["_beginMs"].asNumber<int64_t>();
                    timespec beginTs = {beginMs/1000, (beginMs%1000)*1000*1000};
                    if (m_minPrevRealtime < beginTs && beginTs < m_maxPrevRealtime)
                        beginTs = beginTs + m_realtimeDiff - m_monotimeDiff;
                    timespec duration = ts.tm - beginTs;
                    //PLUGIN_INFO("        end1 (%10lld.%03d)", item.first.tm.tv_sec, item.first.tm.tv_nsec/(1000*1000));
                    //PLUGIN_INFO("      begin1 (%10lld.%03d)", beginMs/1000, (beginMs%1000)*1000*1000);
                    //PLUGIN_INFO("        end2 (%10lld.%03d)", ts.tm.tv_sec, ts.tm.tv_nsec/(1000*1000));
                    //PLUGIN_INFO("      begin2 (%10lld.%03d)", beginTs.tv_sec, beginTs.tv_nsec/(1000*1000));
                    //PLUGIN_INFO("    duration (%10lld.%03d)", duration.tv_sec, duration.tv_nsec/(1000*1000));
                    if (duration.tv_sec < 0) {
                        PLUGIN_WARN("Weird duration: lastPrevRealtime (%10lld.%03d), end (%10lld.%03d), _begin (%10lld.%03d)", m_maxPrevRealtime.tv_sec, m_maxPrevRealtime.tv_nsec/(1000*1000), item.first.tm.tv_sec, item.first.tm.tv_nsec/(1000*1000), beginMs/1000, (beginMs%1000)*1000*1000);
                        kv.second.put("durationSec", 0);
                    } else {
                        kv.second.put("durationSec", (int64_t)duration.tv_sec);
                    }
                    kv.second.remove("_beginMs");
                }
                // object extra : common logic including appExecution case
                MSGPackUtil::putValue(packer, "extra", kv.second);
                PLUGIN_INFO("  extra: %s", kv.second.stringify().c_str());
            }
            m_pendings.pop_front();
        }
    }
    m_isTimeSyncDone = true;
}

bool WebOSSystemdFilter::packCommonMsg(msgpack_unpacked* result, flb_time* timestamp, msgpack_packer* packer, size_t mapSize)
{
    msgpack_pack_array(packer, 2);
    flb_pack_time_now(packer);
    msgpack_pack_map(packer, mapSize);

    MSGPackUtil::putValue(packer, "timestamp", Time::toISO8601(&timestamp->tm));
    MSGPackUtil::putValue(packer, "deviceInfo", m_deviceInfo);
    return true;
}

void WebOSSystemdFilter::handlePowerOn(msgpack_unpacked* result, msgpack_packer* packer)
{
    if (m_isPowerOnDone)
        return;

    string message;
    if (!MSGPackUtil::getValue(&result->data.via.array.ptr[1], "MESSAGE", message))
        return;
    // I tried to consider the "SIGNAL_boot-done" as Power On,
    // But, the time at which "SIGNAL_boot-done" comes is recorded as 1970-01-01 00:00:14 GMT.
    // So, in order to know the exact time (or date) of Power On,
    // I consider the time when LunaSysService synchronizes with the ntp server as Power On.
    // Sample:
    // [] [pmlog] LunaSysService SYSTEM_TIME_UPDATED {"SOURCE":"ntp","PRIORITY":5,"NEXT_SYNC":1663289641} Updated system time
    if (message.rfind("[] [pmlog] LunaSysService SYSTEM_TIME_UPDATED", 0) == string::npos) {
        PLUGIN_DEBUG("MESSAGE: %s", message.c_str());
        return;
    }
    PLUGIN_INFO("MESSAGE: %s", message.c_str());

    msgpack_object* map;
    flb_time timestamp;
    flb_time_pop_from_msgpack(&timestamp, result, &map);

    if (!isTimeSyncDone()) {
        JValue object = Object();
        object.put("event", "powerOn");
        PLUGIN_INFO("Q(%02u) = [%10lld.%03ld] %s", m_pendings.size(), timestamp.tm.tv_sec, timestamp.tm.tv_nsec/(1000*1000), object.stringify().c_str());
        pushEvent(make_pair(timestamp, object));
        m_isPowerOnDone = true;
        processPendings(result, packer);
        return;
    }

    if (!packCommonMsg(result, &timestamp, packer, 3))
        return;
    MSGPackUtil::putValue(packer, "event", "powerOn");
    m_isPowerOnDone = true;
    PLUGIN_INFO("Event (powerOn)");
}

void WebOSSystemdFilter::handleAppExecution(msgpack_unpacked* result, msgpack_packer* packer)
{
    string message;
    if (!MSGPackUtil::getValue(&result->data.via.array.ptr[1], "MESSAGE", message))
        return;
    PLUGIN_DEBUG("MESSAGE: %s", message.c_str());
    smatch match;
    if (!regex_match(message, match, regex("^\\[I\\]\\[RunningApp\\]\\[setLifeStatus\\]\\[([[:print:]]+)\\] Changed: ([[:print:]]+) \\(([[:alpha:]]+) ==> ([[:alpha:]]+)\\)")))
        return;

    const string& instanceId = match[1];
    const string& appId = match[2];
    const string& prevState = match[3];
    const string& currState = match[4];

    if (prevState != "foreground" && currState != "foreground")
        return;

    msgpack_object* map;
    flb_time timestamp;
    flb_time_pop_from_msgpack(&timestamp, result, &map);

    if (timestamp.tm.tv_sec < EPOCHTIME_20220101) {
        // To get the time spent using an app, the timestamps of start time and end time must have the same type.
        // At the beginning of booting, the monotonic time from the booting is recorded, and then the real time comes.
        // So, only the time after 20220101 is considered as normal time, and calculate the spent times.
        // PLUGIN_WARN("Not normal timestamp(%10ld.%03d) %s (%s)", timestamp.tm.tv_sec, timestamp.tm.tv_nsec/(1000*1000), instanceId.c_str(), appId.c_str());
        // return;
    }

    if (currState == "foreground") {
        PLUGIN_INFO("Foreground (%10ld.%03d) %s (%s)", timestamp.tm.tv_sec, timestamp.tm.tv_nsec/(1000*1000), instanceId.c_str(), appId.c_str());
        m_instanceId2timestamp[instanceId] = timestamp;
        return;
    }
    // prevState == foreground
    auto it = m_instanceId2timestamp.find(instanceId);
    if (it == m_instanceId2timestamp.end()) {
        PLUGIN_WARN("Cannot find start time for %s (%s)", instanceId.c_str(), appId.c_str());
        return;
    }

    flb_time duration;
    flb_time_diff(&timestamp, &it->second, &duration);
    PLUGIN_INFO("Background (%10ld.%03d) %s (%s)", timestamp.tm.tv_sec, timestamp.tm.tv_nsec/(1000*1000), instanceId.c_str(), appId.c_str());
    // ignore 0 sec or less than 1 sec.
    if (duration.tm.tv_sec == 0)
        return;

    if (!isTimeSyncDone()) {
        JValue object = Object();
        object.put("event", "appExecution");
        object.put("main", appId);
        JValue extra = Object();
        extra.put("_beginMs", ((int64_t)it->second.tm.tv_sec*1000L) + it->second.tm.tv_nsec/(1000*1000));
        object.put("extra", extra);
        PLUGIN_INFO("Q(%02u) = [%10lld.%03ld] %s", m_pendings.size(), timestamp.tm.tv_sec, timestamp.tm.tv_nsec/(1000*1000), object.stringify().c_str());
        pushEvent(make_pair(timestamp, object));
        return;
    }

    if (!packCommonMsg(result, &timestamp, packer, 5))
        return;
    MSGPackUtil::putValue(packer, "event", "appExecution");
    MSGPackUtil::putValue(packer, "main", appId);
    JValue extra = Object();
    extra.put("durationSec", (int64_t)duration.tm.tv_sec);
    MSGPackUtil::putValue(packer, "extra", extra);
    PLUGIN_INFO("Event (appExecution), Main (%s), Extra %s", appId.c_str(), extra.stringify().c_str());
}

void WebOSSystemdFilter::handleAppUsage(msgpack_unpacked* result, msgpack_packer* packer)
{
    string message;
    if (!MSGPackUtil::getValue(&result->data.via.array.ptr[1], "MESSAGE", message))
        return;
    PLUGIN_DEBUG("MESSAGE: %s", message.c_str());
    smatch match;
    // [] [pmlog] com.webos.app.home DATA_COLLECTION { "main":"com.webos.app.home", "sub": "appbar/launchpad", "event": "click", "extra": { "clickeditem":"com.webos.app.settings" }}
    // [] [pmlog] com.webos.app.home DATA_COLLECTION { "main":"com.webos.app.home", "sub": "launchpad", "event": "swipe", "extra": { "swipedirection":"left/right" }}
    // [] [pmlog] com.webos.app.home DATA_COLLECTION { "main":"com.webos.app.home", "sub": "launchpad", "event": "pagination", "extra":{ "pagenumber":"1/2" }} free style msg
    if (!regex_match(message, match, regex("^\\[\\] \\[pmlog\\] ([[:graph:]]+) DATA_COLLECTION ([[:print:]]+)")))
        return;

    const string& appId = match[1];
    const string& logmsg = match[2];
    size_t jsonEndPos = logmsg.rfind("}");
    if (jsonEndPos == string::npos) {
        PLUGIN_WARN("Not json format: %s", logmsg.c_str());
        return;
    }
    const string& json = logmsg.substr(0, jsonEndPos+1);
    PLUGIN_INFO("%s %s %s", appId.c_str(), json.c_str(), logmsg.substr(jsonEndPos+1).c_str());
    JValue jsonObj = JDomParser::fromString(json);
    if (jsonObj.isNull()) {
        PLUGIN_WARN("Json format error: %s", json.c_str());
        return;
    }

    msgpack_object* map;
    flb_time timestamp;
    flb_time_pop_from_msgpack(&timestamp, result, &map);

    if (!isTimeSyncDone()) {
        PLUGIN_INFO("Q(%02u) = [%10lld.%03ld] %s", m_pendings.size(), timestamp.tm.tv_sec, timestamp.tm.tv_nsec/(1000*1000), jsonObj.stringify().c_str());
        pushEvent(make_pair(timestamp, jsonObj));
        return;
    }

    if (!packCommonMsg(result, &timestamp, packer, 6))
        return;
    string event;
    string main;
    string sub;
    JValue extra = Object();
    (void) JValueUtil::getValue(jsonObj, "event", event);
    (void) JValueUtil::getValue(jsonObj, "main", main);
    (void) JValueUtil::getValue(jsonObj, "sub", sub);
    (void) JValueUtil::getValue(jsonObj, "extra", extra);
    MSGPackUtil::putValue(packer, "event", event);
    MSGPackUtil::putValue(packer, "main", main);
    MSGPackUtil::putValue(packer, "sub", sub);
    MSGPackUtil::putValue(packer, "extra", extra);
    PLUGIN_INFO("Event (%s), Main (%s), Sub (%s), Extra %s", event.c_str(), main.c_str(), sub.c_str(), extra.stringify().c_str());
}

void WebOSSystemdFilter::handleErrorLog(msgpack_unpacked* result, msgpack_packer* packer, const string& priority)
{
    // [20.258192000, {"PRIORITY"=>"3", "_TRANSPORT"=>"syslog", "SYSLOG_IDENTIFIER"=>"wpa_supplicant", "MESSAGE"=>"dbus: wpa_dbus_property_changed: no property SessionLength in object /fi/w1/wpa_supplicant1/Interfaces/0", ..}]
    // [1663118699.932891000, {"_TRANSPORT"=>"syslog", "PRIORITY"=>"3", "SYSLOG_IDENTIFIER"=>"WebAppMgr", "MESSAGE"=>"[] [pmlog] wam.log ERROR {} E[868:930:ne/wayland/window.cc(275)] "Shell type not set. Setting it to TopLevel\n"", ..}]
    // [1663118579.977513000, {"PRIORITY"=>"6", "_TRANSPORT"=>"stdout", "SYSLOG_IDENTIFIER"=>"connman.sh", "MESSAGE"=>"connmand[1057]: wlan0 {RX} 3 packets 288 bytes", ..}]
    // [1663119423.924824000, {"PRIORITY"=>"4", "_TRANSPORT"=>"kernel", "SYSLOG_IDENTIFIER"=>"kernel", "MESSAGE"=>"IPv4: martian source 192.168.0.255 from 192.168.0.15, on dev wlan0", .."}]

    string transport;
    string syslogIdentifier;
    string message;
    if (!MSGPackUtil::getValue(&result->data.via.array.ptr[1], "_TRANSPORT", transport))
        PLUGIN_WARN("Not exist: _TRANSPORT");
    if (!MSGPackUtil::getValue(&result->data.via.array.ptr[1], "SYSLOG_IDENTIFIER", syslogIdentifier))
        PLUGIN_WARN("Not exist: SYSLOG_IDENTIFIER");
    if (!MSGPackUtil::getValue(&result->data.via.array.ptr[1], "MESSAGE", message))
        PLUGIN_WARN("Not exist: MESSAGE");

    msgpack_object* map;
    flb_time timestamp;
    flb_time_pop_from_msgpack(&timestamp, result, &map);

    if (!isTimeSyncDone()) {
        JValue object = Object();
        object.put("event", "error");
        object.put("main", transport);
        object.put("sub", syslogIdentifier);
        PLUGIN_INFO("Q(%02u) = [%10lld.%03ld] %s", m_pendings.size(), timestamp.tm.tv_sec, timestamp.tm.tv_nsec/(1000*1000), object.stringify().c_str());
        JValue extra = Object();
        extra.put("message", message);
        extra.put("priority", priority);
        object.put("extra", extra);
        pushEvent(make_pair(timestamp, object));
        return;
    }

    if (!packCommonMsg(result, &timestamp, packer, 6))
        return;
    MSGPackUtil::putValue(packer, "event", "error");
    MSGPackUtil::putValue(packer, "main", transport);
    MSGPackUtil::putValue(packer, "sub", syslogIdentifier);
    JValue extra = Object();
    extra.put("message", message);
    extra.put("priority", priority);
    MSGPackUtil::putValue(packer, "extra", extra);
    PLUGIN_INFO("Event (error), Main (%s), Sub (%s), Extra %s", transport.c_str(), syslogIdentifier.c_str(), extra.stringify().c_str());
}
