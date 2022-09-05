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

#include "JiraHandler.h"

#include <regex>
#include <sstream>
#include <sys/xattr.h>

#include "Environment.h"
#include "util/File.h"
#include "util/JValueUtil.h"
#include "util/Logger.h"
#include "util/MSGPackUtil.h"
#include "util/PluginConf.h"

#define PATH_OPKG_CHECKSUM      "/var/luna/preferences/opkg_checksum"
#define DEFAULT_TIME_FILE       "/lib/systemd/systemd"
#define PROPS_CONF_FILE         "conf_file"
#define PROPS_EXCEPTIONS        "EXCEPTIONS"
#define COREDUMP_WEBOS_CONF     "jira_webos.conf"

#define KEY_SUMMARY             "summary"
#define KEY_DESCRIPTION         "description"
#define KEY_UPLOAD_FILES        "upload-files"
#define KEY_USERNAME            "username"
#define KEY_PASSWORD            "password"
#define KEY_PRIORITY            "priority"
#define KEY_REPRODUCIBILITY     "reproducibility"
#define KEY_COMM_PID            "comm.pid"
#define KEY_COREDUMP            "coredump"
#define KEY_CRASHREPORT         "crashreport"
#define KEY_JOURNALS            "journals"
#define KEY_MESSAGES            "messages"
#define KEY_SCREENSHOT          "screenshot"
#define KEY_SYSINFO             "sysinfo"

#define STR_LEN                 1024

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
    , m_isNFSMode(false)
{
    PLUGIN_INFO();
    setClassName("JiraHandler");
    m_defaultTime = { 0, 0, 0, 0, 0, 0 };
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

    if (initDefaultTime() == -1) {
        PLUGIN_ERROR("Failed to initialize default time information");
    }
    PLUGIN_INFO("Default (%s) file time information : mtime (%d-%d-%d), ctime (%d-%d-%d) ",
                DEFAULT_TIME_FILE,
                m_defaultTime.modify_year, m_defaultTime.modify_mon, m_defaultTime.modify_mday,
                m_defaultTime.change_year, m_defaultTime.change_mon, m_defaultTime.change_mday);

    initDistroInfo();
    PLUGIN_INFO("Distro : (%s)", m_distro.c_str());

    initOpkgChecksum();
    PLUGIN_INFO("Official checksum : (%s)", m_officialChecksum.c_str());

    string cmdline = File::readFile("/proc/cmdline");
    if (cmdline.find("nfsroot=") != string::npos)
        m_isNFSMode = true;
    PLUGIN_INFO("NFS : (%s)", m_isNFSMode ? "Yes" : "No");

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

    // Read conf file
    string exceptionsFilePath;
    PluginConf pluginConf;
    tmp = flb_output_get_property(PROPS_CONF_FILE, ins);
    if (tmp) {
        if (tmp[0] == '/')
            exceptionsFilePath = tmp;
        else
            exceptionsFilePath = string(config->conf_path) + tmp;
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

    string command = "webos_uploader.py --sync-config";
    PLUGIN_INFO("%s", command.c_str());
    FILE *fp = popen(command.c_str(), "r");
    if (fp == NULL) {
        PLUGIN_WARN("Failed to popen : %s", command.c_str());
    } else {
        char buff[1024];
        while (fgets(buff, 1024, fp)) {
            buff[strlen(buff)-1] = '\0';
            PLUGIN_INFO("%s", buff);
        }
        pclose(fp);
    }

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
    // in_bugreport still uses out_jira plugin.
    string description;
    string upload_files;
    string username;
    string password;
    string priority;
    string reproducibility;
    // newly added for in_coredump
    string commPid;
    string coredump;
    string crashreport;
    string journals;
    string messages;
    string screenshot;
    string sysinfo;
    string command;
    string comm;
    string pid;
    string exe;
    string crashedFunc;

    if (m_isNFSMode) {
        PLUGIN_WARN("NFS mode");
        FLB_OUTPUT_RETURN(FLB_OK);
        return;
    }
    if (checkOpkgChecksum() == -1) {
        PLUGIN_WARN("Not official opkg");
        FLB_OUTPUT_RETURN(FLB_OK);
        return;
    }

    bool isCrashReport = (string::npos != string(tag, tag_len).find("crashinfo"));

    msgpack_unpacked_init(&message);
    while (msgpack_unpack_next(&message, (const char*)data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        PLUGIN_DEBUG("while loop: off=%d, bytes=%d", off, bytes);
        /* unpack the array of [timestamp, payload] */
        if (-1 == flb_time_pop_from_msgpack(&timestamp, &message, &payload)) {
            PLUGIN_ERROR("Failed in flb_time_pop_from_msgpack");
            continue;
        }

        if (MSGPackUtil::getValue(payload, KEY_SUMMARY, summary)) {
            PLUGIN_INFO("summary : %s", summary.c_str());
        }
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

        if (parseCoredumpComm(coredump, comm, pid, exe) == -1) {
            PLUGIN_ERROR("Fail to parse coredump file");
            continue;
        }
        PLUGIN_INFO("comm : (%s), pid : (%s), exe (%s)", comm.c_str(), pid.c_str(), exe.c_str());
        if (checkExeTime(exe) == -1) {
            PLUGIN_WARN("Not official exe file");
            continue;
        }
        if (isExceptedExe(exe)) {
            PLUGIN_WARN("The exe file exists in exception list.");
            continue;
        }
        if (summary.empty()) {
            if (!getCrashedFunction(crashreport.c_str(), comm, crashedFunc)) {
                PLUGIN_WARN("Failed to find crashed function");
                crashedFunc = "";
            }
            summary = "[RDX_CRASH][" + m_distro + "] " + exe + " " + crashedFunc;
        }

        command = "webos_issue.py --summary \'" + summary + "\' "
                + (username.empty() ? "" : "--id '" + username + "' ")
                + (password.empty() ? "" : "--pw '" + password + "' ")
                + (description.empty() ? "" : "--description '" + description + "' ")
                + (priority.empty() ? "" : "--priority " + priority + " ")
                + (reproducibility.empty() ? "" : "--reproducibility \"" + reproducibility + "\" ")
                + (isCrashReport ? "--unique-summary --attach-crashcounter --without-sysinfo --without-screenshot --upload-files \'" + coredump + "\' " + crashreport + " " + journals + " " + messages + " " + screenshot + " " + sysinfo
                                 : "--enable-popup " + (upload_files.empty() ? "" : "--upload-files " + upload_files));
        PLUGIN_INFO("command : %s", command.c_str());

        int ret = system(command.c_str());
        if (ret == -1) {
            PLUGIN_ERROR("Failed to fork : %s", strerror(errno));
        } else if (WIFEXITED(ret) && WEXITSTATUS(ret) == 0) {
            PLUGIN_INFO("Done");
        } else {
            PLUGIN_ERROR("Command terminated with failure : Return code (0x%x), exited (%d), exit-status (%d)", ret, WIFEXITED(ret), WEXITSTATUS(ret));
        }
    }
    msgpack_unpacked_destroy(&message);
    FLB_OUTPUT_RETURN(FLB_OK);
}

int JiraHandler::initDefaultTime()
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

void JiraHandler::initDistroInfo()
{
    int cnt = 0;

    m_distro = "";
    for (int i=0; i < strlen(WEBOS_TARGET_DISTRO); i++) {
        if (*(WEBOS_TARGET_DISTRO+i) == '-')
            continue;

        m_distro += *(WEBOS_TARGET_DISTRO+i);
    }
}

int JiraHandler::initOpkgChecksum()
{
    FILE *fp;
    int ret;
    char checksum_result[STR_LEN];

    fp = fopen(PATH_OPKG_CHECKSUM, "r");
    if (fp != NULL) {
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

    fp = fopen(PATH_OPKG_CHECKSUM, "w");
    if (fp == NULL) {
        PLUGIN_ERROR("Failed fopen");
        return -1;
    }

    fputs(checksum_result, fp);

    fclose(fp);

    PLUGIN_INFO("Create opkg checksum file : (%s)", PATH_OPKG_CHECKSUM);
    return 0;
}

int JiraHandler::checkOpkgChecksum()
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

int JiraHandler::parseCoredumpComm(const string& coredump, string& comm, string& pid, string& exe)
{
    // template : core | comm | uid | boot id | pid | timestamp
    // example  : core.coreexam.0.5999de4a29fb442eb75fb52f8eb64d20.1476.1615253999000000.xz

    ssize_t buflen, keylen, vallen;
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

bool JiraHandler::getCrashedFunction(const string& crashreport, const string& comm, string& func)
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

int JiraHandler::checkExeTime(const string& exe)
{
    PLUGIN_INFO("Check time of (%s) file", exe.c_str());

    struct stat exe_stat;

    struct tm *exe_tm_mtime;
    struct tm *exe_tm_ctime;

    struct time_information exe_time;

    if (lstat(exe.c_str(), &exe_stat) == -1) {
        PLUGIN_ERROR("Failed lstat (%s)", exe.c_str());
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

bool JiraHandler::isExceptedExe(const string& exe)
{
    for (string& exception : m_exceptions) {
        if (strstr(exe.c_str(), exception.c_str()) != NULL) {
            return true;
        }
    }
    return false;
}

