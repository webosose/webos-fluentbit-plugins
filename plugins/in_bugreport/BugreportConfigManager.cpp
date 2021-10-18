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
    m_config = getConfig();
    return true;
}

bool BugreportConfigManager::finalize()
{
    PLUGIN_INFO();
    return true;
}

JValue BugreportConfigManager::getConfig()
{
    // we can return m_config, but the owner that manages jira password is webos_issue.py script,
    // so run py script again.
    string command = "webos_issue.py --show-id";
    PLUGIN_DEBUG("command : %s", command.c_str());
    FILE *fp = popen(command.c_str(), "r");
    if (fp == NULL) {
        PLUGIN_ERROR("Failed to popen : %s", command.c_str());
        return m_config.duplicate();
    }
    char username[64];
    char password[64];
    fscanf(fp, "ID : %s\n", username);
    fscanf(fp, "PW : %s\n", password);
    PLUGIN_DEBUG("id (%s), pw (%s)", username, password);
    m_config.put("username", username);
    m_config.put("password", password);
    pclose(fp);
    return m_config.duplicate();
}

bool BugreportConfigManager::setConfig(const string& username, const string& b64encodedPassword)
{
    // TODO check if username/password can login to jira
    string command = "webos_issue.py --id " + username + " --pw " + b64encodedPassword;
    PLUGIN_DEBUG("command : %s", command.c_str());
    int ret = system(command.c_str());
    if (ret == -1) {
        PLUGIN_ERROR("Failed to fork : %s", strerror(errno));
        return false;
    }
    if (!WIFEXITED(ret) || WEXITSTATUS(ret) != 0) {
        PLUGIN_ERROR("Command terminated with failure : Return code (0x%x), exited (%d), exit-status (%d)", ret, WIFEXITED(ret), WEXITSTATUS(ret));
        return false;
    }
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
