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
        PLUGIN_WARN("Not normal timestamp(%10ld.%03d) %s (%s)", timestamp.tm.tv_sec, timestamp.tm.tv_nsec/(1000*1000), instanceId.c_str(), appId.c_str());
        return;
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
    if (!packCommonMsg(result, &timestamp, packer, 5))
        return;
    MSGPackUtil::putValue(packer, "event", "appExecution");
    MSGPackUtil::putValue(packer, "main", appId);
    JValue extra = Object();
    extra.put("durationSec", duration.tm.tv_sec);
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
