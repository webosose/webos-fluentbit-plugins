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

// Exit status when setting username / password in webos_issue.py
#define EXIT_STATUS_SUCCESS                 0
#define EXIT_STATUS_INVALID_REQUEST_PARAMS  3
#define EXIT_STATUS_LOGIN_FAILED            4

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
    string stdout, stderr, errmsg;
    if (!File::popen(command, stdout, stderr, NULL, errmsg)) {
        PLUGIN_ERROR("Failed to webos_issue.py : %s", errmsg.c_str());
        return m_config.duplicate();
    }
    if (!stderr.empty()) {
        PLUGIN_WARN(" ! %s", stderr.c_str());
    }
    gchar** lines = g_strsplit(stdout.c_str(), "\n", 2);
    guint len = g_strv_length(lines);
    if (len < 2) {
        PLUGIN_WARN(" > %s", stdout.c_str());
        g_strfreev(lines);
        return m_config.duplicate();
    }
    char username[64];
    char password[64];
    if (sscanf(lines[0], "ID : %63s\n", username) != 1)
        PLUGIN_WARN("Failed to read ID");
    if (sscanf(lines[1], "PW : %63s\n", password) != 1)
        PLUGIN_WARN("Failed to read PW");
    g_strfreev(lines);
    PLUGIN_DEBUG("id (%s), pw (%s)", username, password);
    JValue account = Object();
    account.put("username", username);
    account.put("password", password);
    m_config.put("account", account);
    return m_config.duplicate();
}

ErrCode BugreportConfigManager::setAccount(JValue& account)
{
    string username, b64encodedPassword;
    if (!JValueUtil::getValue(account, "username", username)) {
        PLUGIN_ERROR("username is required");
        return ErrCode_INVALID_REQUEST_PARAMS;
    }
    if (!JValueUtil::getValue(account, "password", b64encodedPassword)) {
        PLUGIN_ERROR("password is required");
        return ErrCode_INVALID_REQUEST_PARAMS;
    }
    if ((username.length() == 0 && b64encodedPassword.length() != 0) ||
            (username.length() != 0 && b64encodedPassword.length() == 0)) {
        PLUGIN_ERROR("both usernamd and password should be set togegher");
        return ErrCode_INVALID_REQUEST_PARAMS;
    }
    // TODO check if username/password can login to jira
    string command = "webos_issue.py --id '" + username + "' --pw '" + b64encodedPassword + "'";
    PLUGIN_DEBUG("command : %s", command.c_str());
    string errmsg;
    int ret;
    if (!File::system(command, &ret, errmsg)) {
        PLUGIN_ERROR("Failed to webos_issue.py : %s", errmsg.c_str());
        return ErrCode_INTERNAL_ERROR;
    }
    if (!WIFEXITED(ret) || WEXITSTATUS(ret) != 0) {
        PLUGIN_ERROR("Command terminated with failure : Return code (0x%x), exited (%d), exit-status (%d)", ret, WIFEXITED(ret), WEXITSTATUS(ret));
        if (WEXITSTATUS(ret) == EXIT_STATUS_INVALID_REQUEST_PARAMS)
            return ErrCode_INVALID_REQUEST_PARAMS;
        if (WEXITSTATUS(ret) == EXIT_STATUS_LOGIN_FAILED)
            return ErrCode_LOGIN_FAILED;
        return ErrCode_INTERNAL_ERROR;
    }
    m_config.put("account", account);
    return ErrCode_NONE;
}

string BugreportConfigManager::getUsername() const
{
    string username;
    if (!JValueUtil::getValue(m_config, "account", "username", username))
        return "";
    return username;
}

string BugreportConfigManager::getPassword() const
{
    string password;
    if (!JValueUtil::getValue(m_config, "account", "password", password))
        return "";
    return password;
}

string BugreportConfigManager::getSummary() const
{
    string foundOn = "[" WEBOS_TARGET_DISTRO "-" WEBOS_TARGET_MACHINE "]";
    string username = getUsername().empty() ? JIRA_DEFAULT_USERNAME : getUsername();
    return foundOn + " " + username + "_" + Time::getCurrentTime("%Y%m%d%H%M");
}

string BugreportConfigManager::getDescription() const
{
    return "<p>Steps To Reproduce:<br>1.<br>2.<br>3.</p><p>Expected Result:</p><p>Actual Result:</p>";
}
