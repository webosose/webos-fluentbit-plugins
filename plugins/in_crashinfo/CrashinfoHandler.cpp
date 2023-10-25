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
#include <regex>
#include <stdio.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <vector>

#include "Environment.h"
#include "util/File.h"
#include "util/Logger.h"
#include "util/MSGPackUtil.h"

#define PATH_COREDUMP_DIRECTORY "/var/lib/systemd/coredump"

#define KEY_SUMMARY             "summary"
#define KEY_COMM                "comm"
#define KEY_EXE                 "exe"
#define KEY_PID                 "pid"
#define KEY_COREDUMP            "coredump"
#define KEY_CRASHREPORT         "crashreport"
#define KEY_JOURNALS            "journals"
#define KEY_MESSAGES            "messages"
#define KEY_SCREENSHOT          "screenshot"
#define KEY_SYSINFO             "sysinfo"
#define KEY_DESCRIPTION         "description"
#define KEY_TCSTEPS             "tcsteps"

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

    initDistroInfo();
    PLUGIN_INFO("Distro : (%s)", m_distro.c_str());

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
        ctx->path = pval;
    else
        ctx->path = PATH_COREDUMP_DIRECTORY;
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
    // Refer gpro.lge.com/c/339235
    // According to the link above, the filename is passed only in IN_CREATE.
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
    string comm;
    string exe;
    string pid;

    ctx->buf_start = 0;
    ssize_t nRead = read(ctx->fd, ctx->buf, sizeof(ctx->buf) - 1);
    if (nRead <= 0) {
        PLUGIN_ERROR("Failed to read data");
        flb_input_collector_pause(ctx->coll_fd, ctx->ins);
        flb_engine_exit(config);
        return -1;
    }
    ctx->buf_len = nRead;
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
        if (parseCoredumpComm(coredumpFullpath.c_str(), comm, pid, exe) == -1) {
            PLUGIN_ERROR("Fail to parse coredump file");
            continue;
        }

        list<string> crashEntries;
        if (!File::listFiles(m_workDir, crashEntries)) {
            PLUGIN_WARN("Cannot list files in %s", m_workDir.c_str());
        }
        for (string& crashEntry : crashEntries) {
            crashEntry = File::join(m_workDir, crashEntry);
        }
        if (m_maxEntries > 0 && crashEntries.size() >= m_maxEntries) {
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

        // vector<string> splitted = split(coredumpFilename, '.');
        // if (splitted.size() != 7) {
        //    // core.<comm>.<uid>.<bootid>.<pid>.<timestamp>.zst
        //     PLUGIN_ERROR("Filename format error: %s", coredumpFilename.c_str());
        //     continue;
        // }
        // string commPid = splitted[1] + "." + splitted[4]; // splitted[1]: comm, splitted[4]: pid
        string crashdir = File::join(m_workDir, comm + "." + pid);
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
        string tcstepsFullpath = File::join(crashdir, "tcsteps.txt");
        // Generate sysinfo, screenshot
        string command = string("webos_capture.py --log-level info")
                       + " --screenshot " + screenshotFullpath
                       + " --messages " + messagesFullpath
                       + " --sysinfo " + sysinfoFullpath
                       + " --tcsteps " + tcstepsFullpath;
        if ((access("/run/systemd/journal/socket", F_OK) == 0)) {
            // Generate crashreport and journals for ose
            // corefile : core.coreexam_exampl.0.c7294e397ec747f98552c7c459f7dc1c.2434.1619053570000000.xz
            // crashreport : corefile-crashreport.txt
            // command : webos_capture.py --coredump corefile crashreport
            command += " --journald " + journalsFullpath;
            command += " --coredump \'" + coredumpFilename + "\' " + crashreportFullpath;
        } else {
            // crashreport is also generated when the coredump is generated by systemd-coredump patch.
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

        string crashedFunc;
        if (!getCrashedFunction(crashreportFullpath, comm, crashedFunc)) {
            PLUGIN_WARN("Failed to find crashed function");
            crashedFunc = "";
        }
        string summary = "[RDX_CRASH][" + m_distro + "] " + exe + " " + crashedFunc;

        msgpack_pack_array(&mp_pck, 2); // time | value
        flb_pack_time_now(&mp_pck);

        // 7~11 pairs
        int childrenSize = 7;
        if (access(coredumpFullpath.c_str(), F_OK) == 0)
            childrenSize++;
        if (access(messagesFullpath.c_str(), F_OK) == 0)
            childrenSize++;
        if (access(journalsFullpath.c_str(), F_OK) == 0)
            childrenSize++;
        if (access(tcstepsFullpath.c_str(), F_OK) == 0)
            childrenSize++;
        msgpack_pack_map(&mp_pck, childrenSize);

        // com.pid, coredump, crashreport, journals, messages, screenshot and sysinfo.
        MSGPackUtil::putValue(&mp_pck, KEY_COMM, comm);
        MSGPackUtil::putValue(&mp_pck, KEY_EXE, exe);
        MSGPackUtil::putValue(&mp_pck, KEY_PID, pid);
        MSGPackUtil::putValue(&mp_pck, KEY_SUMMARY, summary);
        if (access(coredumpFullpath.c_str(), F_OK) == 0)
            MSGPackUtil::putValue(&mp_pck, KEY_COREDUMP, coredumpFullpath);
        MSGPackUtil::putValue(&mp_pck, KEY_CRASHREPORT, crashreportFullpath);
        if (access(journalsFullpath.c_str(), F_OK) == 0)
            MSGPackUtil::putValue(&mp_pck, KEY_JOURNALS, journalsFullpath);
        if (access(messagesFullpath.c_str(), F_OK) == 0)
            MSGPackUtil::putValue(&mp_pck, KEY_MESSAGES, messagesFullpath);
        MSGPackUtil::putValue(&mp_pck, KEY_SCREENSHOT, screenshotFullpath);
        MSGPackUtil::putValue(&mp_pck, KEY_SYSINFO, sysinfoFullpath);
        if (access(tcstepsFullpath.c_str(), F_OK) == 0)
            MSGPackUtil::putValue(&mp_pck, KEY_TCSTEPS, tcstepsFullpath);
    }

    // flush to fluentbit
    flb_input_chunk_append_raw(ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return 0;
}

void InCrashinfoHandler::initDistroInfo()
{
    int cnt = 0;

    m_distro = "";
    for (int i=0; i < strlen(WEBOS_TARGET_DISTRO); i++) {
        if (*(WEBOS_TARGET_DISTRO+i) == '-')
            continue;

        m_distro += *(WEBOS_TARGET_DISTRO+i);
    }
}

int InCrashinfoHandler::verifyCoredumpFile(const char *corefile)
{
    size_t len = strlen(corefile);

    if (strncmp(corefile, "core", 4) != 0)
        return -1;

    if (strncmp(corefile + (len-4), ".zst", 4) != 0 && strncmp(corefile + (len-3), ".xz", 3) != 0)
        return -1;

    return 0;
}

int InCrashinfoHandler::parseCoredumpComm(const string& coredump, string& comm, string& pid, string& exe)
{
    // template : core | comm | uid | boot id | pid | timestamp
    // example  : core.coreexam.0.5999de4a29fb442eb75fb52f8eb64d20.1476.1615253999000000.xz

    ssize_t buflen, vallen;
    size_t keylen;
    char exe_str[STR_LEN];
    char *buf, *key, *val;

    PLUGIN_INFO("Full param : (%s)", coredump.c_str());

    // Determine the length of the buffer needed.
    buflen = listxattr(coredump.c_str(), NULL, 0);
    if (buflen == -1) {
        PLUGIN_ERROR("Failed listxattr");
        return -1;
    }
    if (buflen == 0) {
        PLUGIN_ERROR("No attributes");
        return -1;
    }

    // Allocate the buffer.
    buf = (char*)malloc(buflen);
    if (buf == NULL) {
        PLUGIN_ERROR("Failed malloc");
        return -1;
    }

    // Copy the list of attribute keys to the buffer
    buflen = listxattr(coredump.c_str(), buf, buflen);
    PLUGIN_DEBUG("buflen : (%d)", buflen);

    if (buflen == -1) {
        return -1;
    } else if (buflen == 0) {
        PLUGIN_ERROR("No attributes full : (%s)", coredump.c_str());
        return -1;
    }

    key = buf;
    while (0 < buflen) {

        // Output attribute key
        PLUGIN_DEBUG("key : (%s)", key);

        // Determine length of the value
        vallen = getxattr(coredump.c_str(), key, NULL, 0);

        if (vallen < 0) {
            PLUGIN_ERROR("Failed getxattr");
        } else if (vallen == 0) {
            PLUGIN_ERROR("No value");
        } else {
            val = (char*)malloc(vallen + 1);
            if (val == NULL) {
                PLUGIN_ERROR("Failed malloc");
                free(buf);
                return -1;
            }

            // Copy value to buffer
            vallen = getxattr(coredump.c_str(), key, val, vallen);
            if (vallen == -1) {
                PLUGIN_ERROR("Failed getxattr");
            } else {
                // Check attribute value (exe, pid)
                val[vallen] = 0;
                PLUGIN_DEBUG("val : (%s)", val);

                if (strstr(key, "pid") != NULL)
                    pid = val;
                if (strstr(key, "exe") != NULL)
                    exe = val;
            }
            free(val);
        }

        // Forward to next attribute key.
        keylen = strlen(key) + 1;
        buflen -= keylen;
        key += keylen;
    }
    free(buf);

    strncpy(exe_str, exe.c_str(), STR_LEN);
    exe_str[STR_LEN-1] = '\0';

    char *ptr = strtok(exe_str, "/");
    while (ptr != NULL)
    {
        PLUGIN_DEBUG("ptr : (%s)", ptr);
        if (strcmp(ptr, "usr") != 0 && strcmp(ptr, "bin") != 0 && strcmp(ptr, "sbin") != 0) {
            comm = ptr;
            break;
        }
        ptr = strtok(NULL, "/");
    }

    return 0;
}

bool InCrashinfoHandler::getCrashedFunction(const string& crashreport, const string& comm, string& func)
{
    // A crashreport contains the following stacktrace.
    // The first line here isn't really helpful: __libc_do_syscall (libc.so.6 + 0x1ade6)
    // So here try to fina a meaningful line: _Z5funcCv (coredump_example + 0xb6e)
    // ...
    // Found module coredump_example with build-id: 331c2591ed23996f271990c41f3775874eff0ba7
    // Stack trace of thread 13609:
    //   #0  0x00000000f7508de6 __libc_do_syscall (libc.so.6 + 0x1ade6)
    //   #1  0x00000000f7517416 __libc_signal_restore_set (libc.so.6 + 0x29416)
    //   #2  0x00000000f7508922 __GI_abort (libc.so.6 + 0x1a922)
    //   #3  0x00000000f753e834 __libc_message (libc.so.6 + 0x50834)
    //   #4  0x00000000f7543606 malloc_printerr (libc.so.6 + 0x55606)
    //   #5  0x00000000f7544bd2 _int_free (libc.so.6 + 0x56bd2)
    //   #6  0x0000000000508b6e _Z5funcCv (coredump_example + 0xb6e)

    std::ifstream contents(crashreport);
    if (!contents) {
        PLUGIN_ERROR("File open error %s (%d)", crashreport.c_str(), errno);
        return false;
    }
    string line;
    smatch match;
    bool matched = false;
    while (getline(contents, line)) {
        PLUGIN_DEBUG(" < %s", line.c_str());
        if (string::npos == line.find("Stack trace of thread"))
            continue;
        break;
    }
    while (getline(contents, line)) {
        // #0  0x0000000000487ba4 _Z5funcCv (coredump_example + 0xba4)
        // #0  0x00000000b6cb3c26 n/a (libc.so.6 + 0x1ac26)
        // #0  0x00000000f7508de6 __libc_do_syscall (libc.so.6 + 0x1ade6)
        // [:graph:] = letters, digits, and punctuation
        // [:print:] = [:graph:] and space
        if (!regex_match(line, match, regex("\\s*#([0-9]+)\\s+0x[0-9a-zA-Z]+\\s+([[:graph:]]+)\\s+([[:print:]]+)"))) {
            PLUGIN_INFO("Not matched: %s", line.c_str());
            continue;
        }
        // string(match[3]) : (coredmp_example + 0xba4)
        // string(match[2]) : _Z5funcCv
        // Summary: /usr/bin/coredump_example 'in _Z5funcCv (coredmp_example + 0xba4)'
        if (match.ready() && match.size() == 4) {
            if (string(match[1]).find("0") == 0) {
                PLUGIN_INFO("Matched with #0  : (%s)", string(match[0]).c_str());
                func = string("in ") + string(match[2]) + " " + string(match[3]);
                matched = true;
            }
            if (string(match[3]).find(comm, 1) == 1) {
                PLUGIN_INFO("Matched with comm: (%s)", string(match[0]).c_str());
                func = string("in ") + string(match[2]) + " " + string(match[3]);
                matched = true;
                break;
            }
        }
    }
    return matched;
}

void InCrashinfoHandler::destroyCoredumpConfig(struct flb_in_coredump_config *ctx)
{
    if (!ctx)
        return;

    flb_free(ctx);
}
