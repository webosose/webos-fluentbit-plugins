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

#include "BugreportScreenshotManager.h"

#include <pbnjson.hpp>

#include "util/File.h"
#include "util/Logger.h"
#include "util/JValueUtil.h"
#include "util/Time.h"

#define DIR_SCREENSHOTS     "/tmp/screenshots"

BugreportScreenshotManager::BugreportScreenshotManager()
    : m_lunaHandle(NULL)
    , m_dir(NULL)
    , m_dirMonitor(NULL)
    , m_dirMonitorId(0)
{
    PLUGIN_INFO();
}

BugreportScreenshotManager::~BugreportScreenshotManager()
{
    PLUGIN_INFO();
}

bool BugreportScreenshotManager::initialize(LunaHandle* lunaHandle)
{
    PLUGIN_INFO("Screenshot dir : %s", DIR_SCREENSHOTS);
    m_lunaHandle = lunaHandle;

    if (!loadScreenshots()) {
        return false;
    }
    GError* error = NULL;
    m_dir = g_file_new_for_path(DIR_SCREENSHOTS);
    if (NULL == (m_dirMonitor = g_file_monitor(m_dir, G_FILE_MONITOR_NONE, NULL, &error))) {
        g_object_unref(m_dir);
        PLUGIN_ERROR("Failed in g_file_monitor : %s", error->message);
        g_error_free(error);
        return false;
    }
    m_dirMonitorId = g_signal_connect(m_dirMonitor,
                                      "changed",
                                      G_CALLBACK(BugreportScreenshotManager::onDirChanged),
                                      this);
    return true;
}

bool BugreportScreenshotManager::finalize()
{
    PLUGIN_INFO();
    if (0 != m_dirMonitorId)
        g_signal_handler_disconnect(m_dirMonitor, m_dirMonitorId);
    if (NULL != m_dirMonitor)
        g_object_unref(m_dirMonitor);
    if (NULL != m_dir)
        g_object_unref(m_dir);
    return true;
}

string BugreportScreenshotManager::captureCompositorOutput()
{
    string prefix = "screenshot_" + Time::getCurrentTime("%Y%m%d%H%M%S");
    string suffix = ".jpg";
    string filename = prefix + suffix;
    string filepath = File::join(DIR_SCREENSHOTS, filename);
    int index = 2;
    while (access(filepath.c_str(), F_OK) == 0) {
        filename = prefix + "_" + to_string(index++) + suffix;
        filepath = File::join(DIR_SCREENSHOTS, filename);
    }
    JValue requestPayload = Object();
    requestPayload.put("output", filepath);
    requestPayload.put("format", "JPG");
    PLUGIN_DEBUG("%s", requestPayload.stringify().c_str());
    auto call = m_lunaHandle->callOneReply("luna://com.webos.surfacemanager/captureCompositorOutput", requestPayload.stringify().c_str());
    auto reply = call.get(LunaHandle::TIMEOUT);
    if (!reply) {
        PLUGIN_ERROR("No reply in %d ms", LunaHandle::TIMEOUT);
        return "";
    }
    if (reply.isHubError()) {
        PLUGIN_ERROR("Hub error : %s", reply.getPayload());
        return "";
    }
    JValue responsePayload = JDomParser::fromString(reply.getPayload());
    bool returnValue = false;
    if (!JValueUtil::getValue(responsePayload, "returnValue", returnValue) || returnValue == false) {
        PLUGIN_ERROR("Return false : %s", responsePayload.stringify().c_str());
        return "";
    }
    PLUGIN_DEBUG("%s", responsePayload.stringify().c_str());
    PLUGIN_INFO("Screenshot captured : %s", filepath.c_str());
    return filepath;
}

void BugreportScreenshotManager::removeScreenshots()
{
    for (string& screenshot : m_screenshots) {
        if (0 == unlink(screenshot.c_str())) {
            PLUGIN_INFO("Screenshot removed : %s", screenshot.c_str());
        } else {
            PLUGIN_WARN("Failed to remove %s : %s", screenshot.c_str(), strerror(errno));
        }
    }
    m_screenshots.clear();
}

const list<string> BugreportScreenshotManager::getScreenshots() const
{
    return m_screenshots;
}

JValue BugreportScreenshotManager::toJson() const
{
    JValue array = Array();
    for (const string& screenshot : m_screenshots) {
        array.append(screenshot);
    }
    return array;
}

string BugreportScreenshotManager::toString() const
{
    string result = "";
    for (const string& screenshot : m_screenshots) {
        result += screenshot + " ";
    }
    if (!result.empty()) {
        result.pop_back();
    }
    return result;
}

void BugreportScreenshotManager::onDirChanged(GFileMonitor *monitor,
                                              GFile *file,
                                              GFile *other_file,
                                              GFileMonitorEvent event,
                                              gpointer user_data)
{
    BugreportScreenshotManager* self = (BugreportScreenshotManager*)user_data;
    if (self == NULL) {
        PLUGIN_ERROR("user_data is null");
        return;
    }
    PLUGIN_INFO();
    (void)self->loadScreenshots();
}

bool BugreportScreenshotManager::loadScreenshots()
{
    PLUGIN_INFO();
    list<string> screenshots;
    if (!File::createDir(DIR_SCREENSHOTS)) {
        PLUGIN_ERROR("Failed to create dir : %s", DIR_SCREENSHOTS);
        return false;
    }
    if (!File::listFiles(DIR_SCREENSHOTS, screenshots)) {
        PLUGIN_ERROR("Failed to read dir : %s", DIR_SCREENSHOTS);
        return false;
    }
    for (string& screenshot : screenshots) {
        screenshot = File::join(DIR_SCREENSHOTS, screenshot);
        PLUGIN_DEBUG("Screenshot %s", screenshot.c_str());
    }
    m_screenshots = screenshots;
    return true;
}
