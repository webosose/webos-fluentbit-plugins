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

#include "BugreportConfigManager.h"

#include "Environment.h"
#include "util/JValueUtil.h"

BugreportConfigManager::BugreportConfigManager()
{
    m_config = Object();
}

BugreportConfigManager::~BugreportConfigManager()
{
}

JValue BugreportConfigManager::getConfig() const
{
    JValue config = m_config.duplicate();
    // TODO list screenshots..
    JValue screenshots = Array();
    screenshots.append("/tmp/capture/screenshot0.jpg");
    screenshots.append("/tmp/capture/screenshot1.jpg");
    screenshots.append("/tmp/capture/screenshot2.jpg");
    config.put("screenshots", screenshots);
    return config;
}

bool BugreportConfigManager::setConfig(const string& username, const string& password)
{
    // TODO check if username/password can login to jira
    // TODO save config to db
    m_config.put("username", username);
    m_config.put("password", password);
    return true;
}

string BugreportConfigManager::getUsername() const
{
    string username;
    if (!JValueUtil::getValue(m_config, "username", username))
        return "";
    return username;
}

string BugreportConfigManager::getPassword() const
{
    string password;
    if (!JValueUtil::getValue(m_config, "password", password))
        return "";
    return password;
}

string BugreportConfigManager::generateJiraSummary() const
{
    string foundOn = "[" WEBOS_TARGET_DISTRO "-" WEBOS_TARGET_MACHINE "]";
    string username = getUsername().empty() ? JIRA_DEFAULT_USERNAME : getUsername();
    auto now = std::chrono::system_clock::now();
    auto timenow = std::chrono::system_clock::to_time_t(now);
    char buff[20];
    std::strftime(buff, sizeof(buff), "%Y%m%d%H%M", std::localtime(&timenow));
    return foundOn + " " + username + "_" + buff;
}
