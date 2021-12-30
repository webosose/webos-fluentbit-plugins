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

#include "BugreportScreenshotManager.h"

#include <pbnjson.hpp>

#include "util/File.h"
#include "util/Logger.h"
#include "util/JValueUtil.h"
#include "util/Time.h"

#define DIR_SCREENSHOTS     "/tmp/screenshots"

BugreportScreenshotManager::BugreportScreenshotManager()
    : m_lunaHandle(NULL)
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

    if (!File::createDir(DIR_SCREENSHOTS)) {
        PLUGIN_ERROR("Failed to create dir : %s", DIR_SCREENSHOTS);
        return false;
    }
    return true;
}

bool BugreportScreenshotManager::finalize()
{
    PLUGIN_INFO();
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
    DIR* dir = opendir(DIR_SCREENSHOTS);
    struct dirent* dirent;
    while ((dirent = readdir(dir)) != NULL) {
        if (strcmp(".", dirent->d_name) == 0)
            continue;
        if (strcmp("..", dirent->d_name) == 0)
            continue;
        string fullpath = File::join(DIR_SCREENSHOTS, dirent->d_name);
        if (0 == unlink(fullpath.c_str())) {
            PLUGIN_INFO("Screenshot removed : %s", fullpath.c_str());
        } else {
            PLUGIN_WARN("Failed to remove %s : %s", fullpath.c_str(), strerror(errno));
        }
    }
    closedir(dir);
}

bool BugreportScreenshotManager::getScreenshots(list<string>& screenshots) const
{
    PLUGIN_INFO();
    list<string> filenames;
    if (!File::createDir(DIR_SCREENSHOTS)) {
        PLUGIN_ERROR("Failed to create dir : %s", DIR_SCREENSHOTS);
        return false;
    }
    if (!File::listFiles(DIR_SCREENSHOTS, filenames)) {
        PLUGIN_ERROR("Failed to read dir : %s", DIR_SCREENSHOTS);
        return false;
    }
    for (string& filename : filenames) {
        string fullpath = File::join(DIR_SCREENSHOTS, filename);
        PLUGIN_DEBUG("Screenshot %s", fullpath.c_str());
        screenshots.emplace_back(fullpath);
    }
    return true;
}

JValue BugreportScreenshotManager::toJson() const
{
    JValue array = Array();
    list<string> screenshots;
    if (!getScreenshots(screenshots)) {
        return array;
    }
    for (const string& screenshot : screenshots) {
        array.append(screenshot);
    }
    return array;
}

string BugreportScreenshotManager::toString() const
{
    string result = "";
    list<string> screenshots;
    if (!getScreenshots(screenshots)) {
        return result;
    }
    for (const string& screenshot : screenshots) {
        result += screenshot + " ";
    }
    if (!result.empty()) {
        result.pop_back();
    }
    return result;
}
