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
#define KEY_COMM                "comm"
#define KEY_EXE                 "exe"
#define KEY_PID                 "pid"
#define KEY_COREDUMP            "coredump"
#define KEY_CRASHREPORT         "crashreport"
#define KEY_JOURNALS            "journals"
#define KEY_MESSAGES            "messages"
#define KEY_SCREENSHOT          "screenshot"
#define KEY_SYSINFO             "sysinfo"
#define KEY_TCSTEPS             "tcsteps"

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

    string command = "webos_uploader.py --sync-config --log-level debug";
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
    string comm;
    string exe;
    string pid;
    string coredump;
    string crashreport;
    string journals;
    string messages;
    string screenshot;
    string sysinfo;
    string tcstepsFullpath;
    string tcsteps;
    string command;
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

    bool isCrashReport = (string::npos != string(tag, tag_len).find("crash")); // crashd crashinfo

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
        if (MSGPackUtil::getValue(payload, KEY_COMM, comm)) {
            PLUGIN_INFO("%s : %s", KEY_COMM, comm.c_str());
        }
        if (MSGPackUtil::getValue(payload, KEY_EXE, exe)) {
            PLUGIN_INFO("%s : %s", KEY_EXE, exe.c_str());
        }
        if (MSGPackUtil::getValue(payload, KEY_PID, pid)) {
            PLUGIN_INFO("%s : %s", KEY_PID, pid.c_str());
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
        if (MSGPackUtil::getValue(payload, KEY_TCSTEPS, tcstepsFullpath)) {
            PLUGIN_INFO("%s : %s", KEY_TCSTEPS, tcstepsFullpath.c_str());
            tcsteps = File::readFile(tcstepsFullpath);
        }

        if (checkExeTime(exe) == -1) {
            PLUGIN_WARN("Not official exe file");
            continue;
        }
        if (isExceptedExe(exe)) {
            PLUGIN_WARN("The exe file exists in exception list.");
            continue;
        }

        string pattern = "\"";
        string replace = "\\\"";
        string::size_type pos = 0;
        string::size_type offset = 0;
        string escapedComment = tcsteps;
        while ((pos = escapedComment.find(pattern, offset)) != string::npos) {
            escapedComment.replace(escapedComment.begin() + pos, escapedComment.begin() + pos + pattern.size(), replace);
            offset = pos + replace.size();
        }
        if (tcsteps.empty())
            escapedComment = "\nCouldn't find any automation test information from the logs.";
        else
            escapedComment = "\nThe following is the automation test information extracted from the logs.\nIt may be related to this crash.\n{code:sql}" + escapedComment + "{code}";
        command = "webos_issue.py --log-level info --summary \'" + summary + "\' "
                + (username.empty() ? "" : "--id '" + username + "' ")
                + (password.empty() ? "" : "--pw '" + password + "' ")
                + (description.empty() ? "" : "--description \"" + description + "\" ")
                + (priority.empty() ? "" : "--priority " + priority + " ")
                + (reproducibility.empty() ? "" : "--reproducibility \"" + reproducibility + "\" ")
                + (isCrashReport ? "--unique-summary --attach-crashcounter --without-sysinfo --without-screenshot --upload-files \'" + coredump + "\' \'" + crashreport + "\' " + journals + " " + messages + " " + screenshot + " " + sysinfo + " "
                                 : "--enable-popup " + (upload_files.empty() ? "" : "--upload-files " + upload_files + " "))
                + "--comment \"" + escapedComment + "\" ";

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

