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

#include "CrashinfoHandler.h"

#include <fcntl.h>
#include <fstream>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

#include "util/File.h"
#include "util/Logger.h"
#include "util/MSGPackUtil.h"

#define PATH_COREDUMP_DIRECTORY "/var/lib/systemd/coredump"

#define KEY_SUMMARY             "summary"
#define KEY_COMM_PID            "comm.pid"
#define KEY_COREDUMP            "coredump"
#define KEY_CRASHREPORT         "crashreport"
#define KEY_JOURNALS            "journals"
#define KEY_MESSAGES            "messages"
#define KEY_SCREENSHOT          "screenshot"
#define KEY_SYSINFO             "sysinfo"

#define STR_LEN                 1024

#define PROPS_WORK_DIR          "work_dir"
#define PATH_TMP_CRASHINFO      "/tmp/crashinfo"
#define PROPS_MAX_ENTRIES       "max_entries"
#define DEFAULT_MAX_ENTRIES     5

extern "C" int initInCrashinfoHandler(struct flb_input_instance *ins, struct flb_config *config, void *data)
{
    return InCrashinfoHandler::getInstance().onInit(ins, config, data);
}

extern "C" int exitInCrashinfoHandler(void *context, struct flb_config *config)
{
    return InCrashinfoHandler::getInstance().onExit(context, config);
}

extern "C" int collectInCrashinfo(struct flb_input_instance *ins, struct flb_config *config, void *context)
{
    return InCrashinfoHandler::getInstance().onCollect(ins, config, context);
}

vector<string> split(const string& str, char delim = '.')
{
    vector<string> v;
    stringstream ss(str);
    string token;
    while (std::getline(ss, token, delim)) {
        v.emplace_back(token);
    }
    return v;
}

InCrashinfoHandler::InCrashinfoHandler()
    : m_workDir(PATH_TMP_CRASHINFO)
    , m_maxEntries(DEFAULT_MAX_ENTRIES)
{
    PLUGIN_INFO();
    setClassName("InCrashinfoHandler");
}

InCrashinfoHandler::~InCrashinfoHandler()
{
    PLUGIN_INFO();
}

int InCrashinfoHandler::onInit(struct flb_input_instance *ins, struct flb_config *config, void *data)
{
    PLUGIN_INFO();

    int fd;
    int ret;
    struct flb_in_coredump_config *ctx;
    (void) data;

    const char *pval = NULL;

    /* Allocate space for the configuration */
    ctx = (struct flb_in_coredump_config*)flb_malloc(sizeof(struct flb_in_coredump_config));
    if (!ctx)
        return -1;

    ctx->buf_len = 0;
    ctx->ins = ins;

    fd = inotify_init();
    if (fd < 0) {
        PLUGIN_ERROR("Failed to init inotify_init");
        goto init_error;
    }

    ctx->fd = fd;
    ctx->buf_start=0;

    // Set the monitoring path for coredump file
    pval = flb_input_get_property("path", ins);
    if (pval)
        ctx->path = (char *)pval;
    else
        ctx->path = (char *)PATH_COREDUMP_DIRECTORY;
    PLUGIN_INFO("Monitoring coredump file path : %s", ctx->path);

    pval = flb_input_get_property(PROPS_WORK_DIR, ins);
    if (pval) {
        m_workDir = pval;
    }
    PLUGIN_INFO("Work_Dir : %s", m_workDir.c_str());
    if (!File::createDir(m_workDir)) {
        PLUGIN_ERROR("Failed to create Dir: %s", m_workDir.c_str());
    }

    pval = flb_input_get_property(PROPS_MAX_ENTRIES, ins);
    if (pval) {
        try {
            m_maxEntries = stoi(pval);
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

    // Always initialize built-in JSON pack state
    flb_pack_state_init(&ctx->pack_state);
    ctx->pack_state.multiple = FLB_TRUE;

    // Set watch descriptor
    ctx->wd = inotify_add_watch(ctx->fd, ctx->path, IN_CREATE);

    // Collect upon data available on the watch event
    ret = flb_input_set_collector_event(ins, collectInCrashinfo, ctx->fd, config);
    if (ret == -1) {
        PLUGIN_ERROR("Failed to set collector_event");
        goto init_error;
    }

    ctx->coll_fd = ret;

    // Set the context
    flb_input_set_context(ins, ctx);

    PLUGIN_INFO("Initialize done");

    return 0;

init_error:
    destroyCoredumpConfig(ctx);
    return -1;
}

int InCrashinfoHandler::onExit(void *context, struct flb_config *config)
{
    PLUGIN_INFO();
    struct flb_in_coredump_config *ctx = (flb_in_coredump_config*)context;

    if (!ctx)
        return 0;

    if (ctx->fd >= 0) {
        close(ctx->fd);
    }

    flb_pack_state_reset(&ctx->pack_state);
    destroyCoredumpConfig(ctx);

    return 0;
}

// According to my test, this function is called once per crash.
// That is, this is called multiple times, if multi processes are crashed.
int InCrashinfoHandler::onCollect(struct flb_input_instance *ins, struct flb_config *config, void *context)
{
    struct flb_in_coredump_config *ctx = (flb_in_coredump_config *)context;
    struct inotify_event *event;

    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    ctx->buf_start = 0;
    ctx->buf_len = read(ctx->fd, ctx->buf, sizeof(ctx->buf) - 1);
    if (ctx->buf_len <= 0) {
        PLUGIN_ERROR("Failed to read data");
        flb_input_collector_pause(ctx->coll_fd, ctx->ins);
        flb_engine_exit(config);
        return -1;
    }
    ctx->buf[ctx->buf_len] = '\0';

    PLUGIN_INFO("Catch the new coredump event");

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    for (; ctx->buf_start + EVENT_SIZE < ctx->buf_len; ctx->buf_start += EVENT_SIZE + event->len) {
        PLUGIN_DEBUG("while loop: buf_start=%d, buf_len=%d", ctx->buf_start, ctx->buf_len);
        event=(struct inotify_event*) (ctx->buf+ctx->buf_start);

        if (event->len == 0) {
            PLUGIN_ERROR("Event length is 0");
            continue;
        }
        if (event->len > ctx->buf_len - ctx->buf_start - EVENT_SIZE) {
            PLUGIN_ERROR("Too long event : %u (start : %d, len : %d)", event->len, ctx->buf_start, ctx->buf_len);
            break;
        }
        if (!(event->mask & IN_CREATE)) {
            PLUGIN_ERROR("Not create event : %s", event->name);
            continue;
        }

        string coredumpFilename = event->name;
        string coredumpFullpath = File::join(ctx->path, coredumpFilename);
        PLUGIN_INFO("New file is created : (%s)", coredumpFullpath.c_str());
        // Guarantee coredump file closing time
        sleep(1);

        if (verifyCoredumpFile(coredumpFilename.c_str()) == -1) {
            PLUGIN_ERROR("Not coredump file");
            continue;
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
                if (stat(crashEntry.c_str(), &attr) == -1) {
                    PLUGIN_WARN("Failed to stat %s: %s", crashEntry.c_str(), strerror(errno));
                    continue;
                }
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

        vector<string> splitted = split(coredumpFilename, '.');
        if (splitted.size() != 7) {
            // core.<comm>.<uid>.<bootid>.<pid>.<timestamp>.zst
            PLUGIN_ERROR("Filename format error: %s", coredumpFilename.c_str());
            continue;
        }
        string commPid = splitted[1] + "." + splitted[4];
        string crashdir = File::join(m_workDir, commPid);
        if (!File::createDir(crashdir)) {
            PLUGIN_ERROR("Failed to create dir: %s: %s", crashdir.c_str(), strerror(errno));
            continue;
        }

        size_t extPos = coredumpFilename.find_last_of('.');
        string crashreportFilename = coredumpFilename.substr(0, extPos) + "-crashreport.txt";
        string crashreportFullpath = File::join(crashdir, crashreportFilename);
        string journalsFullpath = File::join(crashdir, "journals.txt");
        string messagesFullpath = File::join(crashdir, "messages.tgz");
        string screenshotFullpath = File::join(crashdir, "screenshot.jpg");
        string sysinfoFullpath = File::join(crashdir, "info.txt");
        // Generate sysinfo, screenshot
        string command = string("webos_capture.py")
                       + " --screenshot " + screenshotFullpath
                       + " --messages " + messagesFullpath
                       + " --sysinfo " + sysinfoFullpath;
        if ((access("/run/systemd/journal/socket", F_OK) == 0)) {
            // Generate crashreport and journals for ose
            // corefile : core.coreexam_exampl.0.c7294e397ec747f98552c7c459f7dc1c.2434.1619053570000000.xz
            // crashreport : corefile-crashreport.txt
            // command : webos_capture.py --coredump corefile crashreport
            command += " --journald " + journalsFullpath;
            command += " --coredump \'" + coredumpFilename + "\' " + crashreportFullpath;
        } else {
            // crashreport is also generted when the coredump is generated by systemd-coredump patch.
            // even if we configure 'Storage=none' (do not store coredump) in /etc/systemd/coredump.conf
            string tmpCrashreport = File::join("/tmp", crashreportFilename);
            ifstream infile(tmpCrashreport.c_str());
            ofstream outfile(File::join(crashdir, crashreportFilename).c_str());
            outfile << infile.rdbuf();
            if (outfile) {
                (void) unlink(tmpCrashreport.c_str());
            } else {
                PLUGIN_ERROR("Failed to copy crashreport: %s", strerror(errno));
                continue;
            }
        }
        PLUGIN_INFO("command : %s", command.c_str());
        int rc = system(command.c_str());
        if (rc == -1) {
            PLUGIN_ERROR("Failed to fork: %s: %s", command.c_str(), strerror(errno));
            continue;
        } else if (WEXITSTATUS(rc)) {
            PLUGIN_ERROR("Failed to capture screenshot. (%d)", WEXITSTATUS(rc));
            continue;
        }

        if (access(crashreportFullpath.c_str(), F_OK) != 0) {
            continue;
        }
        PLUGIN_INFO("The crashreport file is created : %s)", crashreportFullpath.c_str());
        // Guarantee crashreport file closing time
        sleep(1);

        msgpack_pack_array(&mp_pck, 2); // time | value
        flb_pack_time_now(&mp_pck);

        // 4~7 pairs
        int childrenSize = 4;
        if (access(coredumpFullpath.c_str(), F_OK) == 0)
            childrenSize++;
        if (access(messagesFullpath.c_str(), F_OK) == 0)
            childrenSize++;
        if (access(journalsFullpath.c_str(), F_OK) == 0)
            childrenSize++;
        msgpack_pack_map(&mp_pck, childrenSize);

        // com.pid, coredump, crashreport, journals, messages, screenshot and sysinfo.
        MSGPackUtil::putValue(&mp_pck, KEY_COMM_PID, commPid);
        if (access(coredumpFullpath.c_str(), F_OK) == 0)
            MSGPackUtil::putValue(&mp_pck, KEY_COREDUMP, coredumpFullpath);
        MSGPackUtil::putValue(&mp_pck, KEY_CRASHREPORT, crashreportFullpath);
        if (access(journalsFullpath.c_str(), F_OK) == 0)
            MSGPackUtil::putValue(&mp_pck, KEY_JOURNALS, journalsFullpath);
        if (access(messagesFullpath.c_str(), F_OK) == 0)
            MSGPackUtil::putValue(&mp_pck, KEY_MESSAGES, messagesFullpath);
        MSGPackUtil::putValue(&mp_pck, KEY_SCREENSHOT, screenshotFullpath);
        MSGPackUtil::putValue(&mp_pck, KEY_SYSINFO, sysinfoFullpath);
    }

    // flush to fluentbit
    flb_input_chunk_append_raw(ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return 0;
}

int InCrashinfoHandler::verifyCoredumpFile(const char *corefile)
{
    int len = strlen(corefile);

    if (strncmp(corefile, "core", 4) != 0)
        return -1;

    if (strncmp(corefile + (len-4), ".zst", 4) != 0 && strncmp(corefile + (len-3), ".xz", 3) != 0)
        return -1;

    return 0;
}

void InCrashinfoHandler::destroyCoredumpConfig(struct flb_in_coredump_config *ctx)
{
    if (!ctx)
        return;

    flb_free(ctx);
}
