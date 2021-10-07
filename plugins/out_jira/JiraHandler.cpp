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

#include "JiraHandler.h"

#include "util/File.h"
#include "util/JValueUtil.h"
#include "util/Logger.h"

#define KEY_SUMMARY             "summary"
#define KEY_UPLOAD_FILES        "upload-files"
#define KEY_USERNAME            "username"
#define KEY_PASSWORD            "password"
#define KEY_PRIORITY            "priority"
#define KEY_REPRODUCIBILITY     "reproducibility"

#define DEFAULT_SCRIPT          "webos_issue.py"

extern "C" int initJiraHandler(struct flb_output_instance *ins, struct flb_config *config, void *data)
{
    return JiraHandler::getInstance().onInit(ins, config, data);
}

extern "C" int exitJiraHandler(void *data, struct flb_config *config)
{
    return JiraHandler::getInstance().onExit(data, config);
}

extern "C" void flushJira(const void *data, size_t bytes, const char *tag, int tag_len, struct flb_input_instance *ins, void *context, struct flb_config *config)
{
    JiraHandler::getInstance().onFlush(data, bytes, tag, tag_len, ins, context, config);
}

JiraHandler::JiraHandler()
    : m_outFormat(FLB_PACK_JSON_FORMAT_LINES)
    , m_jsonDateFormat(FLB_PACK_JSON_DATE_DOUBLE)
    , m_jsonDateKey(NULL)
{
    PLUGIN_INFO();
    setClassName("JiraHandler");
}

JiraHandler::~JiraHandler()
{
    PLUGIN_INFO();
}

int JiraHandler::onInit(struct flb_output_instance *ins, struct flb_config *config, void *data)
{
    PLUGIN_INFO();

    int ret;
    const char *tmp;
    struct flb_jira_config *ctx = NULL;

    // Set format
    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        ret = flb_pack_to_json_format_type(tmp);
        if (ret == -1)
            PLUGIN_ERROR("unrecognized 'format' option");
        else
            m_outFormat = ret;
    }

    // Set date format
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        ret = flb_pack_to_json_date_type(tmp);
        if (ret == -1)
            PLUGIN_ERROR("unrecognized 'json_date_format' option");
        else
            m_jsonDateFormat = ret;
    }

    // Set date key
    tmp = flb_output_get_property("json_date_key", ins);
    if (tmp)
        m_jsonDateKey = flb_sds_create(tmp);
    else
        m_jsonDateKey = flb_sds_create("date");

    // Set script
    tmp = flb_output_get_property("script", ins);
    if (tmp)
        m_jiraScript = tmp;
    else
        m_jiraScript = DEFAULT_SCRIPT;
    PLUGIN_INFO("Jira script : %s", m_jiraScript.c_str());

    // Export context
    flb_output_set_context(ins, ctx);
    PLUGIN_INFO("initialize done");
    return 0;
}

int JiraHandler::onExit(void *data, struct flb_config *config)
{
    PLUGIN_INFO();

    if (m_jsonDateKey) {
        flb_sds_destroy(m_jsonDateKey);
        m_jsonDateKey = NULL;
    }
    return 0;
}

void JiraHandler::onFlush(const void *data, size_t bytes, const char *tag, int tag_len, struct flb_input_instance *ins, void *context, struct flb_config *config)
{
    PLUGIN_INFO();

    flb_sds_t json;
    JValue object;
    string summary;
    string upload_files;
    string username;
    string password;
    string priority;
    string reproducibility;
    string command;
    bool isCrashReport = (string::npos != string(tag, tag_len).find("coredump"));

    json = flb_pack_msgpack_to_json_format((const char*)data, bytes, m_outFormat, m_jsonDateFormat, m_jsonDateKey);
    PLUGIN_DEBUG("%s", json);

    object = JDomParser::fromString(json);
    flb_sds_destroy(json);

    if (!JValueUtil::getValue(object, KEY_SUMMARY, summary)) {
        PLUGIN_ERROR("failed to get summary on (%s)", object.stringify().c_str());
        FLB_OUTPUT_RETURN(FLB_OK);
        return;
    }
    PLUGIN_INFO("summary : %s", summary.c_str());

    if (!JValueUtil::getValue(object, KEY_UPLOAD_FILES, upload_files)) {
        PLUGIN_ERROR("failed to get upload-files on (%s)", object.stringify().c_str());
        FLB_OUTPUT_RETURN(FLB_OK);
        return;
    }
    PLUGIN_INFO("upload-files : %s", upload_files.c_str());

    if (JValueUtil::getValue(object, KEY_USERNAME, username)) {
        PLUGIN_INFO("username : %s", username.c_str());
    }
    if (JValueUtil::getValue(object, KEY_PASSWORD, password)) {
        PLUGIN_INFO("password : %s", password.c_str());
    }
    if (JValueUtil::getValue(object, KEY_PRIORITY, priority)) {
        PLUGIN_INFO("priority : %s", priority.c_str());
    }
    if (JValueUtil::getValue(object, KEY_REPRODUCIBILITY, reproducibility)) {
        PLUGIN_INFO("reproducibility : %s", reproducibility.c_str());
    }

    // template : command --summary XXX --unique-summary --upload-files YYY
    // example  : webos_issue.py --summary "[CRASH][OSE] bootd" --unique-summary --upload-files core.bootd.0.....xz

    command = "webos_issue.py --summary \'" + summary + "\' "
            + (username.empty() ? "" : "--id " + username + " ")
            + (password.empty() ? "" : "--pw " + password + " ")
            + (priority.empty() ? "" : "--priority " + priority + " ")
            + (reproducibility.empty() ? "" : "--reproducibility \'" + reproducibility + "\' ")
            + (isCrashReport ? "--unique-summary --attach-crashcounter " : "")
            + "--upload-files " + upload_files;
    PLUGIN_INFO("command : %s", command.c_str());

    int ret = system(command.c_str());

    FLB_OUTPUT_RETURN(FLB_OK);
}
