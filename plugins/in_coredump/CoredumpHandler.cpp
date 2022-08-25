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

#include "CoredumpHandler.h"

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
#include "util/PluginConf.h"

#define PATH_COREDUMP_DIRECTORY "/var/lib/systemd/coredump"
#define PATH_OPKG_CEHCKSUM      "/var/luna/preferences/opkg_checksum"

#define DEFAULT_TIME_FILE       "/lib/systemd/systemd"

#define KEY_SUMMARY             "summary"
#define KEY_COMM_PID            "comm.pid"
#define KEY_COREDUMP            "coredump"
#define KEY_CRASHREPORT         "crashreport"
#define KEY_JOURNALS            "journals"
#define KEY_MESSAGES            "messages"
#define KEY_SCREENSHOT          "screenshot"
#define KEY_SYSINFO             "sysinfo"

#define STR_LEN                 1024

#define PROPS_CONF_FILE         "conf_file"
#define PROPS_EXCEPTIONS        "EXCEPTIONS"
#define COREDUMP_WEBOS_CONF     "coredump_webos.conf"
#define PROPS_WORK_DIR          "work_dir"
#define PATH_TMP_CRASH          "/tmp/crash"
#define PROPS_MAX_ENTRIES       "max_entries"
#define DEFAULT_MAX_ENTRIES     5

extern "C" int initCoredumpHandler(struct flb_input_instance *ins, struct flb_config *config, void *data)
{
    return CoredumpHandler::getInstance().onInit(ins, config, data);
}

extern "C" int exitCoredumpHandler(void *context, struct flb_config *config)
{
    return CoredumpHandler::getInstance().onExit(context, config);
}

extern "C" int collectCoredump(struct flb_input_instance *ins, struct flb_config *config, void *context)
{
    return CoredumpHandler::getInstance().onCollect(ins, config, context);
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

CoredumpHandler::CoredumpHandler()
    : m_isNFSMode(false)
    , m_workDir(PATH_TMP_CRASH)
    , m_maxEntries(DEFAULT_MAX_ENTRIES)
{
    PLUGIN_INFO();
    setClassName("CoredumpHandler");
    m_defaultTime = { 0, 0, 0, 0, 0, 0 };
}

CoredumpHandler::~CoredumpHandler()
{
    PLUGIN_INFO();
}

int CoredumpHandler::onInit(struct flb_input_instance *ins, struct flb_config *config, void *data)
{
    PLUGIN_INFO();

    int fd;
    int ret;
    struct flb_in_coredump_config *ctx;
    (void) data;

    const char *pval = NULL;

    string exceptionsFilePath;
    PluginConf pluginConf;

    if (initDefaultTime() == -1) {
        PLUGIN_ERROR("Failed to initialize default time information");
    }
    PLUGIN_INFO("Default (%s) file time information : mtime (%d-%d-%d), ctime (%d-%d-%d) ", \
            DEFAULT_TIME_FILE, \
            m_defaultTime.modify_year, m_defaultTime.modify_mon, m_defaultTime.modify_mday, \
            m_defaultTime.change_year, m_defaultTime.change_mon, m_defaultTime.change_mday);

    initDistroInfo();
    PLUGIN_INFO("Distro : (%s)", m_distroResult.c_str());

    initOpkgChecksum();
    PLUGIN_INFO("Official checksum : (%s)", m_officialChecksum.c_str());

    string cmdline = File::readFile("/proc/cmdline");
    if (cmdline.find("nfsroot=") != string::npos)
        m_isNFSMode = true;
    PLUGIN_INFO("NFS : (%s)", m_isNFSMode ? "Yes" : "No");

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

    pval = flb_input_get_property(PROPS_CONF_FILE, ins);
    if (pval) {
        if (pval[0] == '/')
            exceptionsFilePath = pval;
        else
            exceptionsFilePath = string(config->conf_path) + pval;
    } else {
        exceptionsFilePath = string(config->conf_path) + COREDUMP_WEBOS_CONF;
    }
    PLUGIN_INFO("Exceptions_File : %s", exceptionsFilePath.c_str());
    pluginConf.readConfFile(exceptionsFilePath.c_str());
    for (const pair<string, string>& kv : pluginConf.getSection(PROPS_EXCEPTIONS)) {
        if (strcasecmp(kv.first.c_str(), "path") == 0) {
            m_exceptions.push_back(kv.second);
        }
    }

    pval = flb_input_get_property(PROPS_WORK_DIR, ins);
    if (pval) {
        m_workDir = pval;
    }
    PLUGIN_INFO("Work_Dir : %s", m_workDir.c_str());
    if (!File::createDir(m_workDir)) {
        PLUGIN_ERROR("Failed to create Dir: %s", m_workDir.c_str());
        return -1;
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
    ret = flb_input_set_collector_event(ins, collectCoredump, ctx->fd, config);
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

int CoredumpHandler::onExit(void *context, struct flb_config *config)
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
int CoredumpHandler::onCollect(struct flb_input_instance *ins, struct flb_config *config, void *context)
{
    struct flb_in_coredump_config *ctx = (flb_in_coredump_config *)context;
    struct inotify_event *event;

    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    char comm[STR_LEN];
    char pid[STR_LEN];
    char exe[STR_LEN];
    char crashed_func[STR_LEN];
    char upload_files[STR_LEN];
    char summary[STR_LEN];

    int ret;
    int len;
    int i;

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


        if (parseCoredumpComm(coredumpFullpath.c_str(), comm, pid, exe) == -1) {
            PLUGIN_ERROR("Fail to parse coredump file");
            continue;
        }
        PLUGIN_INFO("comm : (%s), pid : (%s), exe (%s)", comm, pid, exe);

        if (m_isNFSMode) {
            PLUGIN_WARN("NFS mode");
            break;
        }

        if (checkOpkgChecksum() == -1) {
            PLUGIN_WARN("Not official opkg");
            break;
        }

        if (checkExeTime(exe) == -1) {
            PLUGIN_WARN("Not official exe file");
            continue;
        }

        if (isExceptedExe(exe)) {
            PLUGIN_WARN("The exe file exists in exception list.");
            continue;
        }

        if (!getCrashedFunction(crashreportFullpath.c_str(), comm, crashed_func)) {
            PLUGIN_WARN("Failed to find crashed function");
            crashed_func[0] = '\0';
        }

        snprintf(upload_files, STR_LEN, "\'%s\' %s", coredumpFullpath.c_str(), crashreportFullpath.c_str());

        msgpack_pack_array(&mp_pck, 2); // time | value
        flb_pack_time_now(&mp_pck);

        // 5~8 pairs
        int childrenSize = 5;
        if (access(coredumpFullpath.c_str(), F_OK) == 0)
            childrenSize++;
        if (access(messagesFullpath.c_str(), F_OK) == 0)
            childrenSize++;
        if (access(journalsFullpath.c_str(), F_OK) == 0)
            childrenSize++;
        msgpack_pack_map(&mp_pck, childrenSize);

        // key : summary | value : [RDX_CRASH][distro] comm
        msgpack_pack_str(&mp_pck, len=strlen(KEY_SUMMARY));
        msgpack_pack_str_body(&mp_pck, KEY_SUMMARY, len);
        snprintf(summary, STR_LEN, "[RDX_CRASH][%s] %s %s", m_distroResult.c_str(), exe, crashed_func);
        msgpack_pack_str(&mp_pck, len=strlen(summary));
        msgpack_pack_str_body(&mp_pck, summary, len);
        PLUGIN_INFO("Add msgpack - key (%s) : val (%s)", KEY_SUMMARY, summary);

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

int CoredumpHandler::initDefaultTime()
{
    struct stat def_stat;
    struct tm *def_tm_mtime;
    struct tm *def_tm_ctime;

    if (lstat(DEFAULT_TIME_FILE, &def_stat) == -1) {
        PLUGIN_ERROR("Failed lstat (%s)", DEFAULT_TIME_FILE);
        return -1;
    }

    def_tm_mtime = localtime(&def_stat.st_mtime);
    def_tm_ctime = localtime(&def_stat.st_ctime);

    m_defaultTime.modify_year = def_tm_mtime->tm_year + 1900;
    m_defaultTime.modify_mon = def_tm_mtime->tm_mon + 1;
    m_defaultTime.modify_mday = def_tm_mtime->tm_mday;
    m_defaultTime.change_year = def_tm_ctime->tm_year + 1900;
    m_defaultTime.change_mon = def_tm_ctime->tm_mon + 1;
    m_defaultTime.change_mday = def_tm_ctime->tm_mday;

    return 0;
}

void CoredumpHandler::initDistroInfo()
{
    int cnt = 0;

    m_distroResult = "";
    for (int i=0; i < strlen(WEBOS_TARGET_DISTRO); i++) {
        if (*(WEBOS_TARGET_DISTRO+i) == '-')
            continue;

        m_distroResult += *(WEBOS_TARGET_DISTRO+i);
    }
}

int CoredumpHandler::initOpkgChecksum()
{
    FILE *fp;
    int ret;
    char checksum_result[STR_LEN];

    if (access(PATH_OPKG_CEHCKSUM, F_OK) == 0) {
        PLUGIN_INFO("Already opkg checksum file is created (%s)", PATH_OPKG_CEHCKSUM);
        fp = fopen(PATH_OPKG_CEHCKSUM, "r");
        if (fp == NULL) {
            PLUGIN_ERROR("Failed fopen");
            return -1;
        }
        fgets(checksum_result, STR_LEN, fp);
        m_officialChecksum = checksum_result;
        fclose(fp);
        return 0;
    }

    fp = popen("opkg info | md5sum | awk \'{print $1}\'", "r");
    if (fp == NULL) {
        PLUGIN_ERROR("Failed popen");
        return -1;
    }

    if (fgets(checksum_result, STR_LEN, fp) == NULL) {
        PLUGIN_ERROR("Failed fgets");
        pclose(fp);
        return -1;
    }
    pclose(fp);

    checksum_result[strlen(checksum_result)-1] = '\0';
    m_officialChecksum = checksum_result;

    fp = fopen(PATH_OPKG_CEHCKSUM, "w");
    if (fp == NULL) {
        PLUGIN_ERROR("Failed fopen");
        return -1;
    }

    fputs(checksum_result, fp);

    fclose(fp);

    PLUGIN_INFO("Create opkg checksum file : (%s)", PATH_OPKG_CEHCKSUM);
    return 0;
}

int CoredumpHandler::verifyCoredumpFile(const char *corefile)
{
    int len = strlen(corefile);

    if (strncmp(corefile, "core", 4) != 0)
        return -1;

    if (strncmp(corefile + (len-4), ".zst", 4) != 0 && strncmp(corefile + (len-3), ".xz", 3) != 0)
        return -1;

    return 0;
}

int CoredumpHandler::parseCoredumpComm(const char *full, char *comm, char *pid, char *exe)
{
    // template : core | comm | uid | boot id | pid | timestamp
    // example  : core.coreexam.0.5999de4a29fb442eb75fb52f8eb64d20.1476.1615253999000000.xz

    ssize_t buflen, keylen, vallen;
    char exe_str[STR_LEN];
    char *buf, *key, *val;

    PLUGIN_INFO("Full param : (%s)", full);

    // Determine the length of the buffer needed.
    buflen = listxattr(full, NULL, 0);
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
    buflen = listxattr(full, buf, buflen);
    PLUGIN_DEBUG("buflen : (%d)", buflen);

    if (buflen == -1) {
        return -1;
    } else if (buflen == 0) {
        PLUGIN_ERROR("No attributes full : (%s)", full);
        return -1;
    }

    key = buf;
    while (0 < buflen) {

        // Output attribute key
        PLUGIN_DEBUG("key : (%s)", key);

        // Determine length of the value
        vallen = getxattr(full, key, NULL, 0);

        if (vallen == -1) {
            PLUGIN_ERROR("Failed getxattr");
        } else if (vallen == 0) {
            PLUGIN_ERROR("No value");
        } else {
            val = (char*)malloc(vallen + 1);
            if (val == NULL) {
                PLUGIN_ERROR("Failed malloc");
                return -1;
            }

            // Copy value to buffer
            vallen = getxattr(full, key, val, vallen);
            if (vallen == -1) {
                PLUGIN_ERROR("Failed getxattr");
            } else {
                // Check attribute value (exe, pid)
                val[vallen] = 0;
                PLUGIN_DEBUG("val : (%s)", val);

                if (strstr(key, "pid") != NULL)
                    snprintf(pid, STR_LEN, "%s", val);
                if (strstr(key, "exe") != NULL)
                    snprintf(exe, STR_LEN, "%s", val);
            }
            free(val);
        }

        // Forward to next attribute key.
        keylen = strlen(key) + 1;
        buflen -= keylen;
        key += keylen;
    }
    free(buf);

    strncpy(exe_str, exe, STR_LEN);
    exe_str[STR_LEN-1] = '\0';

    char *ptr = strtok(exe_str, "/");
    while (ptr != NULL)
    {
        PLUGIN_DEBUG("ptr : (%s)", ptr);
        if (strcmp(ptr, "usr") != 0 && strcmp(ptr, "bin") != 0 && strcmp(ptr, "sbin") != 0) {
            snprintf(comm, STR_LEN, "%s", ptr);
            break;
        }
        ptr = strtok(NULL, "/");
    }

    return 0;
}

int CoredumpHandler::checkOpkgChecksum()
{
    FILE *fp;
    int ret;
    char checksum_result[STR_LEN];

    fp = popen("opkg info | md5sum | awk \'{print $1}\'", "r");
    if (fp == NULL) {
        PLUGIN_ERROR("Failed popen");
        return -1;
    }

    if (fgets(checksum_result, STR_LEN, fp) == NULL) {
        PLUGIN_ERROR("Failed fgets");
        pclose(fp);
        return -1;
    }
    pclose(fp);

    checksum_result[strlen(checksum_result)-1] = '\0';

    PLUGIN_INFO("Default checksum (%s), now (%s)", m_officialChecksum.c_str(), checksum_result);

    if (strcmp(m_officialChecksum.c_str(), checksum_result) == 0)
        return 0;
    else
        return -1;
}

int CoredumpHandler::checkExeTime(const char *exe)
{
    PLUGIN_INFO("Check time of (%s) file", exe);

    struct stat exe_stat;

    struct tm *exe_tm_mtime;
    struct tm *exe_tm_ctime;

    struct time_information exe_time;

    if (lstat(exe, &exe_stat) == -1) {
        PLUGIN_ERROR("Failed lstat (%s)", exe);
        return -1;
    }

    exe_tm_mtime = localtime(&exe_stat.st_mtime);
    exe_tm_ctime = localtime(&exe_stat.st_ctime);

    exe_time.modify_year = exe_tm_mtime->tm_year + 1900;
    exe_time.modify_mon = exe_tm_mtime->tm_mon + 1;
    exe_time.modify_mday = exe_tm_mtime->tm_mday;
    exe_time.change_year = exe_tm_ctime->tm_year + 1900;
    exe_time.change_mon = exe_tm_ctime->tm_mon + 1;
    exe_time.change_mday = exe_tm_ctime->tm_mday;

    PLUGIN_INFO("Modified time information default mtime (%d-%d-%d), exe mtime (%d-%d-%d)", \
            m_defaultTime.modify_year, m_defaultTime.modify_mon, m_defaultTime.modify_mday, \
            exe_time.modify_year, exe_time.modify_mon, exe_time.modify_mday);
    PLUGIN_INFO("Changed time information default ctime (%d-%d-%d), exe ctime (%d-%d-%d)", \
            m_defaultTime.change_year, m_defaultTime.change_mon, m_defaultTime.change_mday, \
            exe_time.change_year, exe_time.change_mon, exe_time.change_mday);

    if (m_defaultTime.modify_year != exe_time.modify_year || m_defaultTime.modify_mon != exe_time.modify_mon || m_defaultTime.modify_mday != exe_time.modify_mday || \
        m_defaultTime.change_year != exe_time.change_year || m_defaultTime.change_mon != exe_time.change_mon || m_defaultTime.change_mday != exe_time.change_mday)
        return -1;

    return 0;
}

bool CoredumpHandler::isExceptedExe(const char *exe)
{
    for (string& exception : m_exceptions) {
        if (strstr(exe, exception.c_str()) != NULL) {
            return true;
        }
    }
    return false;
}

bool CoredumpHandler::getCrashedFunction(const char *crashreport, const char *comm, char *func)
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
        PLUGIN_ERROR("File open error %s (%d)", crashreport, errno);
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
                snprintf(func, STR_LEN, "in %s", string(match[2]).c_str(), string(match[3]).c_str());
                matched = true;
            }
            if (string(match[3]).find(comm, 1) == 1) {
                PLUGIN_INFO("Matched with comm: (%s)", string(match[0]).c_str());
                snprintf(func, STR_LEN, "in %s %s", string(match[2]).c_str(), string(match[3]).c_str());
                matched = true;
                break;
            }
        }
    }
    return matched;
}

void CoredumpHandler::destroyCoredumpConfig(struct flb_in_coredump_config *ctx)
{
    if (!ctx)
        return;

    flb_free(ctx);
}
