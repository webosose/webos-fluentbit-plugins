// Copyright (c) 2022 LG Electronics, Inc.
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

#include "CrashinfoHandler.h"

#include <list>
#include <sstream>

#include "util/File.h"
#include "util/JValueUtil.h"
#include "util/MSGPackUtil.h"
#include "util/Logger.h"

#define KEY_COMM_PID                "comm.pid"
#define KEY_COREDUMP                "coredump"
#define KEY_CRASHREPORT             "crashreport"
#define KEY_JOURNALS                "journals"
#define KEY_MESSAGES                "messages"
#define KEY_SCREENSHOT              "screenshot"
#define KEY_SYSINFO                 "sysinfo"

#define PROPS_WORK_DIR              "work_dir"
#define PATH_VAR_SPOOL_CRASHINFO    "/var/spool/crashinfo"
#define PROPS_MAX_ENTRIES           "max_entries"
#define DEFAULT_MAX_ENTRIES         5


extern "C" int initOutCrashinfoHandler(struct flb_output_instance *ins, struct flb_config *config, void *data)
{
    return OutCrashinfoHandler::getInstance().onInit(ins, config, data);
}

extern "C" int exitOutCrashinfoHandler(void *data, struct flb_config *config)
{
    return OutCrashinfoHandler::getInstance().onExit(data, config);
}

extern "C" void flushOutCrashinfo(const void *data, size_t bytes, const char *tag, int tag_len, struct flb_input_instance *ins, void *context, struct flb_config *config)
{
    OutCrashinfoHandler::getInstance().onFlush(data, bytes, tag, tag_len, ins, context, config);
}

OutCrashinfoHandler::OutCrashinfoHandler()
    : m_workDir(PATH_VAR_SPOOL_CRASHINFO)
    , m_maxEntries(DEFAULT_MAX_ENTRIES)
{
    PLUGIN_INFO();
    setClassName("OutCrashinfoHandler");
}

OutCrashinfoHandler::~OutCrashinfoHandler()
{
    PLUGIN_INFO();
}

int OutCrashinfoHandler::onInit(struct flb_output_instance *ins, struct flb_config *config, void *data)
{
    PLUGIN_INFO();

    int ret;
    const char *tmp;
    struct flb_jira_config *ctx = NULL;

    tmp = flb_output_get_property(PROPS_WORK_DIR, ins);
    if (tmp) {
        m_workDir = tmp;
    }
    PLUGIN_INFO("Work_Dir : %s", m_workDir.c_str());
    if (!File::createDir(m_workDir)) {
        PLUGIN_ERROR("Failed to create Dir: %s", m_workDir.c_str());
        return -1;
    }

    tmp = flb_output_get_property(PROPS_MAX_ENTRIES, ins);
    if (tmp) {
        try {
            m_maxEntries = stoi(tmp);
        } catch (const exception& e) {
            PLUGIN_WARN("Failed to get Max_Entries: %s", e.what());
        }
        if (m_maxEntries < 1) {
            PLUGIN_WARN("Max_Entries : %d => 1. (Minimum)", m_maxEntries);
            m_maxEntries = 1;
        }
    } else {
        PLUGIN_INFO("Max_Entries : %d", m_maxEntries);
    }

    // Export context
    flb_output_set_context(ins, ctx);
    PLUGIN_INFO("initialize done");
    return 0;
}

int OutCrashinfoHandler::onExit(void *data, struct flb_config *config)
{
    PLUGIN_INFO();

    return 0;
}

void OutCrashinfoHandler::onFlush(const void *data, size_t bytes, const char *tag, int tag_len, struct flb_input_instance *ins, void *context, struct flb_config *config)
{
    PLUGIN_INFO();

    msgpack_unpacked message;
    size_t off = 0;
    struct flb_time timestamp;
    msgpack_object* payload;

    string commPid;
    string coredump;
    string crashreport;
    string journals;
    string messages;
    string screenshot;
    string sysinfo;

    msgpack_unpacked_init(&message);
    while (msgpack_unpack_next(&message, (const char*)data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        PLUGIN_DEBUG("while loop: off=%d, bytes=%d", off, bytes);
        /* unpack the array of [timestamp, payload] */
        if (-1 == flb_time_pop_from_msgpack(&timestamp, &message, &payload)) {
            PLUGIN_ERROR("Failed in flb_time_pop_from_msgpack");
            continue;
        }

        if (MSGPackUtil::getValue(payload, KEY_COMM_PID, commPid)) {
            PLUGIN_INFO("%s : %s", KEY_COMM_PID, commPid.c_str());
        }
        if (MSGPackUtil::getValue(payload, KEY_COREDUMP, coredump)) {
            PLUGIN_INFO("%s : %s", KEY_COREDUMP, coredump.c_str());
        }
        if (MSGPackUtil::getValue(payload, KEY_CRASHREPORT, crashreport)) {
            PLUGIN_INFO("%s : %s", KEY_CRASHREPORT, crashreport.c_str());
        }
        if (MSGPackUtil::getValue(payload, KEY_JOURNALS, journals)) {
            PLUGIN_INFO("%s : %s", KEY_JOURNALS, journals.c_str());
        }
        if (MSGPackUtil::getValue(payload, KEY_MESSAGES, messages)) {
            PLUGIN_INFO("%s : %s", KEY_MESSAGES, messages.c_str());
        }
        if (MSGPackUtil::getValue(payload, KEY_SCREENSHOT, screenshot)) {
            PLUGIN_INFO("%s : %s", KEY_SCREENSHOT, screenshot.c_str());
        }
        if (MSGPackUtil::getValue(payload, KEY_SYSINFO, sysinfo)) {
            PLUGIN_INFO("%s : %s", KEY_SYSINFO, sysinfo.c_str());
        }

        list<string> crashEntries;
        if (!File::listFiles(m_workDir, crashEntries)) {
            PLUGIN_WARN("Cannot list files in %s", m_workDir.c_str());
        }
        for (string& crashEntry : crashEntries) {
            crashEntry = File::join(m_workDir, crashEntry);
        }
        if (crashEntries.size() >= m_maxEntries) {
            crashEntries.sort(File::compareWithCtime);
            for (const string& crashEntry : crashEntries) {
                struct stat attr;
                stat(crashEntry.c_str(), &attr);
                PLUGIN_INFO("ctime: (%ld), m_time: (%ld), entry: (%s)", attr.st_ctime, attr.st_mtime, crashEntry.c_str());
            }
            for (size_t i = crashEntries.size(); i >= m_maxEntries; i--) {
                const string& outdated = crashEntries.front();
                PLUGIN_INFO("Remove outdated %s", outdated.c_str());
                if (!File::removeDir(outdated)) {
                    PLUGIN_WARN("Failed to remove %s", outdated.c_str());
                }
                crashEntries.pop_front();
            }
        }

        string command = string("tar zcf ") + File::join(m_workDir, commPid + ".tgz ") + "-C / "
                       // coredump is not generated in MP build.
                       + (access(coredump.c_str(), F_OK) == 0 ? coredump : "") + " "
                       + crashreport + " " + journals + " " + messages + " " + screenshot + " " + sysinfo;
        PLUGIN_INFO("command : %s", command.c_str());
        int rc = system(command.c_str());
        if (rc == -1) {
            PLUGIN_ERROR("Failed to fork : %s", strerror(errno));
        } else if (WIFEXITED(rc) && WEXITSTATUS(rc) == 0) {
            PLUGIN_INFO("Done");
        } else {
            PLUGIN_ERROR("Command terminated with failure : Return code (0x%x), exited (%d), exit-status (%d)", rc, WIFEXITED(rc), WEXITSTATUS(rc));
        }
    }
    msgpack_unpacked_destroy(&message);
    FLB_OUTPUT_RETURN(FLB_OK);
}
