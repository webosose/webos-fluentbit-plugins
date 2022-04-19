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

#include "Environment.h"
#include "util/File.h"
#include "util/Logger.h"
#include "util/PluginConf.h"

#define PATH_COREDUMP_DIRECTORY "/var/lib/systemd/coredump"
#define PATH_OPKG_CEHCKSUM      "/var/luna/preferences/opkg_checksum"

#define DEFAULT_SCRIPT          "webos_capture.py"
#define DEFAULT_TIME_FILE       "/lib/systemd/systemd"

#define KEY_SUMMARY             "summary"
#define KEY_UPLOAD_FILES        "upload-files"

#define STR_LEN                 1024

#define CONF_FILE               "conf_file"
#define COREDUMP_WEBOS_CONF     "coredump_webos.conf"
#define EXCEPTIONS              "EXCEPTIONS"

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

CoredumpHandler::CoredumpHandler()
    : m_isNFSMode(false)
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
    PLUGIN_INFO("Default (%s) file time information :  mtime (%d-%d-%d), ctime (%d-%d-%d) ", \
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

    // Set the crashreport script
    pval = flb_input_get_property("script", ins);
    if (pval)
        ctx->crashreport_script = pval;
    else
        ctx->crashreport_script = DEFAULT_SCRIPT;
    PLUGIN_INFO("Crashreport script : %s", ctx->crashreport_script);

    pval = flb_input_get_property(CONF_FILE, ins);
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
    for (const pair<string, string>& kv : pluginConf.getSection(EXCEPTIONS)) {
        if (strcasecmp(kv.first.c_str(), "path") == 0) {
            m_exceptions.push_back(kv.second);
        }
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

int CoredumpHandler::onCollect(struct flb_input_instance *ins, struct flb_config *config, void *context)
{
    struct flb_in_coredump_config *ctx = (flb_in_coredump_config *)context;
    struct inotify_event *event;

    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    char full_path[STR_LEN];
    char comm[STR_LEN];
    char pid[STR_LEN];
    char exe[STR_LEN];
    char corefile[STR_LEN];
    char crashreport[STR_LEN];
    char crashed_func[STR_LEN];
    char upload_files[STR_LEN];
    char summary[STR_LEN];

    int ret;
    int len;
    int i;

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
        PLUGIN_DEBUG("while loop: buf_start=%u, buf_len=%u", ctx->buf_start, ctx->buf_len);
        event=(struct inotify_event*) &ctx->buf[ctx->buf_start];

        if (event->len == 0) {
            PLUGIN_ERROR("Event length is 0");
            continue;
        }

        if (!(event->mask & IN_CREATE)) {
            PLUGIN_ERROR("Not create event : %s", event->name);
            continue;
        }

        snprintf(full_path, STR_LEN, "%s/%s", ctx->path, event->name);
        PLUGIN_INFO("New file is created : (%s)", full_path);
        strncpy(corefile, event->name, strlen(event->name));

        // Guarantee coredump file closing time
        sleep(1);

        if (verifyCoredumpFile(event->name) == -1) {
            PLUGIN_ERROR("Not coredump file");
            continue;
        }

        if (parseCoredumpComm(full_path, comm, pid, exe) == -1) {
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

        if ((access("/run/systemd/journal/socket", F_OK) == 0)) {
            // For consistency, change the crash report path to /tmp.
            sprintf(crashreport, "%s/%s-crashreport.txt", "/tmp", event->name);
            createCrashreport(ctx->crashreport_script, event->name, crashreport);
        } else {
            string filename = event->name;
            size_t extPos = filename.find_last_of('.');
            sprintf(crashreport, "/tmp/%s-crashreport.txt", filename.substr(0, extPos).c_str());
        }

        if (access(crashreport, F_OK) != 0) {
            PLUGIN_ERROR("Failed to create crashreport : %s", crashreport);
            continue;
        }
        PLUGIN_INFO("The crashreport file is created : %s)", crashreport);

        // Guarantee crashreport file closing time
        sleep(1);

        if (!getCrashedFunction(crashreport, crashed_func)) {
            PLUGIN_WARN("Failed to find crashed function");
            crashed_func[0] = '\0';
        }

        snprintf(upload_files, STR_LEN, "\'%s\' %s", full_path, crashreport);

        msgpack_pack_array(&mp_pck, 2); // time | value
        flb_pack_time_now(&mp_pck);

        // 2 pairs
        msgpack_pack_map(&mp_pck, 2);

        // key : upload-files | value : coredump file path & crashreport path
        msgpack_pack_str(&mp_pck, len=strlen(KEY_UPLOAD_FILES));
        msgpack_pack_str_body(&mp_pck, KEY_UPLOAD_FILES, len);
        msgpack_pack_str(&mp_pck, len=strlen(upload_files));
        msgpack_pack_str_body(&mp_pck, upload_files, len);
        PLUGIN_INFO("Add msgpack - key (%s) : val (%s)", KEY_UPLOAD_FILES, upload_files);

        // key : summary | value : [RDX_CRASH][distro] comm
        msgpack_pack_str(&mp_pck, len=strlen(KEY_SUMMARY));
        msgpack_pack_str_body(&mp_pck, KEY_SUMMARY, len);

        snprintf(summary, STR_LEN, "[RDX_CRASH][%s] %s %s", m_distroResult.c_str(), exe, crashed_func);
        msgpack_pack_str(&mp_pck, len=strlen(summary));
        msgpack_pack_str_body(&mp_pck, summary, len);
        PLUGIN_INFO("Add msgpack - key (%s) : val (%s)", KEY_SUMMARY, summary);
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
                    strcpy(pid, val);
                if (strstr(key, "exe") != NULL)
                    strcpy(exe, val);
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
            strcpy(comm, ptr);
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

int CoredumpHandler::createCrashreport(const char *script, const char *corefile, const char *crashreport)
{
    // corefile : core.coreexam_exampl.0.c7294e397ec747f98552c7c459f7dc1c.2434.1619053570000000.xz
    // crashreport : corefile-crashreport.txt
    // command : webos_capture.py --coredump corefile crashreport

    char command[STR_LEN];
    sprintf(command, "%s --coredump \'%s\' %s", script, corefile, crashreport);
    PLUGIN_INFO("command : %s", command);

    int ret = system(command);

    return 0;
}

bool CoredumpHandler::getCrashedFunction(const char* crashreport, char* func)
{
    std::ifstream contents(crashreport);
    if (!contents) {
        PLUGIN_ERROR("File open error %s (%d)", crashreport, errno);
        return false;
    }
    string line;
    smatch match;
    while (getline(contents, line)) {
        if (string::npos == line.find("Stack trace of thread"))
            continue;
        getline(contents, line);
        PLUGIN_INFO("Stacktrace : %s", line.c_str());
        // #0  0x0000000000487ba4 _Z5funcCv (coredump_example + 0xba4)
        // #0  0x00000000b6cb3c26 n/a (libc.so.6 + 0x1ac26)
        if (!regex_match(line, match, regex("\\s*#0\\s+0x([0-9a-zA-Z]+)\\s+([[:print:]]+)"))) {
            PLUGIN_DEBUG("Not matched");
        }
        break;
    }
    if (!match.ready() || match.size() != 3) {
        PLUGIN_ERROR("Cannot find stack trace.");
        return false;
    }
    // summary: /usr/bin/coredump_example in _Z5funcCv (coredmp_example + 0xba4)
    snprintf(func, STR_LEN, "in %s", string(match[2]).c_str());
    return true;
}

void CoredumpHandler::destroyCoredumpConfig(struct flb_in_coredump_config *ctx)
{
    if (!ctx)
        return;

    flb_free(ctx);
}
