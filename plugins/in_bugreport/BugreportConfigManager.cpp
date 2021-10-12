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
#include "util/File.h"
#include "util/Logger.h"
#include "util/JValueUtil.h"
#include "util/Time.h"

const string BugreportConfigManager::DIR_CONFIG = WEBOS_INSTALL_PREFERENCESDIR "/com.webos.service.bugreport";
const string BugreportConfigManager::FILE_CONFIG_JSON = "config.json";

BugreportConfigManager::BugreportConfigManager()
{
    PLUGIN_INFO();
    m_config = Object();
}

BugreportConfigManager::~BugreportConfigManager()
{
    PLUGIN_INFO();
}

bool BugreportConfigManager::initialize()
{
    PLUGIN_INFO();

    if (!File::createDir(DIR_CONFIG)) {
        PLUGIN_WARN("Failed to mkdir : %s", DIR_CONFIG.c_str());
        return false;
    }
    load();
    return true;
}

bool BugreportConfigManager::finalize()
{
    PLUGIN_INFO();
    return true;
}

JValue BugreportConfigManager::getConfig() const
{
    return m_config.duplicate();
}

bool BugreportConfigManager::setConfig(const string& username, const string& password)
{
    // TODO check if username/password can login to jira
    // TODO save encrypted config to db
    m_config.put("username", username);
    m_config.put("password", password);
    save();
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
    return foundOn + " " + username + "_" + Time::getCurrentTime("%Y%m%d%H%M");
}

void BugreportConfigManager::load()
{
    PLUGIN_INFO();
    m_config = JDomParser::fromFile(File::join(DIR_CONFIG, FILE_CONFIG_JSON).c_str());
    if (m_config.isNull()) {
        m_config = Object();
    }
}

void BugreportConfigManager::save()
{
    PLUGIN_DEBUG();
    if (!File::writeFile(File::join(DIR_CONFIG, FILE_CONFIG_JSON), m_config.stringify("    "))) {
        PLUGIN_WARN("Failed to write config");
    }
}
