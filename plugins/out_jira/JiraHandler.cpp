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

#include <sstream>

#include "util/File.h"
#include "util/JValueUtil.h"
#include "util/MSGPackUtil.h"
#include "util/Logger.h"

#define KEY_SUMMARY             "summary"
#define KEY_DESCRIPTION         "description"
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
    msgpack_unpacked message;
    size_t off = 0;
    struct flb_time timestamp;
    msgpack_object* payload;
    string summary;
    string description;
    string upload_files;
    string username;
    string password;
    string priority;
    string reproducibility;
//    msgpack_object* componentsObj;
//    list<string> components;
//    string componentsStr = "";
    string command;
    bool isCrashReport = (string::npos != string(tag, tag_len).find("coredump"));

    msgpack_unpacked_init(&message);
    while (msgpack_unpack_next(&message, (const char*)data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        PLUGIN_DEBUG("while loop: off=%d, bytes=%d", off, bytes);
        /* unpack the array of [timestamp, payload] */
        if (-1 == flb_time_pop_from_msgpack(&timestamp, &message, &payload)) {
            PLUGIN_ERROR("Failed in flb_time_pop_from_msgpack");
            continue;
        }
        if (!MSGPackUtil::getValue(payload, KEY_SUMMARY, summary)) {
            PLUGIN_ERROR("Failed to get summary");
            continue;
        }
        PLUGIN_INFO("summary : %s", summary.c_str());

        if (MSGPackUtil::getValue(payload, KEY_DESCRIPTION, description)) {
            PLUGIN_INFO("description : %s", description.c_str());
        }
        if (MSGPackUtil::getValue(payload, KEY_UPLOAD_FILES, upload_files)) {
            PLUGIN_INFO("upload-files : %s", upload_files.c_str());
        }
        if (MSGPackUtil::getValue(payload, KEY_USERNAME, username)) {
            PLUGIN_INFO("username : %s", username.c_str());
        }
        if (MSGPackUtil::getValue(payload, KEY_PASSWORD, password)) {
            PLUGIN_INFO("password : %s", password.c_str());
        }
        if (MSGPackUtil::getValue(payload, KEY_PRIORITY, priority)) {
            PLUGIN_INFO("priority : %s", priority.c_str());
        }
        if (MSGPackUtil::getValue(payload, KEY_REPRODUCIBILITY, reproducibility)) {
            PLUGIN_INFO("reproducibility : %s", reproducibility.c_str());
        }
//        if (MSGPackUtil::getValue(payload, KEY_COMPONENTS, &componentsObj)) {
//            // TODO Support array in MSGPackUtil
//            for (uint32_t idx = 0; idx < componentsObj->via.array.size; ++idx) {
//                string component = string(componentsObj->via.array.ptr[idx].via.str.ptr, componentsObj->via.array.ptr[idx].via.str.size);
//                components.emplace_back(component);
//                PLUGIN_INFO("component : %s", component.c_str());
//                componentsStr += "--components \'" + component + "\' ";
//            }
//        }

        // template : command --summary XXX --unique-summary --upload-files YYY
        // example  : webos_issue.py --summary "[CRASH][OSE] bootd" --unique-summary --upload-files core.bootd.0.....xz

        command = "webos_issue.py --summary \'" + summary + "\' "
                + (username.empty() ? "" : "--id '" + username + "' ")
                + (password.empty() ? "" : "--pw '" + password + "' ")
                + (description.empty() ? "" : "--description '" + description + "' ")
                + (priority.empty() ? "" : "--priority " + priority + " ")
                + (reproducibility.empty() ? "" : "--reproducibility \"" + reproducibility + "\" ")
                + (isCrashReport ? "--unique-summary --attach-crashcounter " : "--enable-popup ")
                + (upload_files.empty() ? "" : "--upload-files " + upload_files);
        PLUGIN_INFO("command : %s", command.c_str());

        int ret = system(command.c_str());
        if (ret == -1) {
            PLUGIN_ERROR("Failed to fork : %s", strerror(errno));
        } else if (WIFEXITED(ret) && WEXITSTATUS(ret) == 0) {
            PLUGIN_INFO("Done");
        } else {
            PLUGIN_ERROR("Command terminated with failure : Return code (0x%x), exited (%d), exit-status (%d)", ret, WIFEXITED(ret), WEXITSTATUS(ret));
        }
        // remove upload-files except core.XXXX.xz
        // TODO remove all file or uploaded file ?
        size_t pos = 0;
        stringstream ss(upload_files);
        string token;
        char delimiter = ' ';
        while (std::getline(ss, token, delimiter)) {
            if (token.rfind("core.", 0) == 0) {
                PLUGIN_DEBUG("Do not remove %s", token.c_str());
                continue;
            }
            if (-1 == unlink(token.c_str())) {
                PLUGIN_WARN("Failed to remove %s : %s", token.c_str(), strerror(errno));
                continue;
            }
            PLUGIN_INFO("Removed %s", token.c_str());
        }
    }
    msgpack_unpacked_destroy(&message);
    FLB_OUTPUT_RETURN(FLB_OK);
}
