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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_engine.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_error.h>

#include <msgpack.h>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <limits.h>

#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include "in_coredump.h"

#define PATH_COREDUMP_DIRECTORY "/var/lib/systemd/coredump"

#define DEFAULT_SCRIPT          "webos_capture.py"
#define DEFAULT_TIME_FILE       "/lib/systemd/systemd"

#define KEY_SUMMARY             "summary"
#define KEY_UPLOAD_FILES        "upload-files"

#define STR_LEN                 1024

struct time_information
{
    int modify_year;
    int modify_mon;
    int modify_mday;

    int change_year;
    int change_mon;
    int change_mday;
};

struct time_information default_time;

static int init_default_time()
{
    flb_info("[in_coredump][%s] init default time information (%s) file", __FUNCTION__, DEFAULT_TIME_FILE);

    struct stat def_stat;

    struct tm *def_tm_mtime;
    struct tm *def_tm_ctime;

    if (lstat(DEFAULT_TIME_FILE, &def_stat) == -1) {
        flb_error("[in_coredump][%s] Failed lstat (%s)", __FUNCTION__, DEFAULT_TIME_FILE);
        return -1;
    }
    def_tm_mtime = localtime(&def_stat.st_mtime);
    def_tm_ctime = localtime(&def_stat.st_ctime);

    default_time.modify_year = def_tm_mtime->tm_year + 1900;
    default_time.modify_mon = def_tm_mtime->tm_mon + 1;
    default_time.modify_mday = def_tm_mtime->tm_mday;
    default_time.change_year = def_tm_ctime->tm_year + 1900;
    default_time.change_mon = def_tm_ctime->tm_mon + 1;
    default_time.change_mday = def_tm_ctime->tm_mday;

    flb_info("[in_coredump][%s] Default time information mtime (%d-%d-%d), ctime (%d-%d-%d)", __FUNCTION__, \
            default_time.modify_year, default_time.modify_mon, default_time.modify_mday, \
            default_time.change_year, default_time.change_mon, default_time.change_mday);

    return 0;
}

static int verify_coredump_file(const char *corefile)
{
    int len = strlen(corefile);

    if (strncmp(corefile, "core", 4) != 0)
        return -1;

    if (corefile[len-3] != '.' && corefile[len-2] && 'x' && corefile[len-1] && 'z')
        return -1;

    return 0;
}

static int parse_coredump_comm(const char *full, char *comm, char *pid, char *exe)
{
    // template : core | comm | uid | boot id | pid | timestamp
    // example  : core.coreexam.0.5999de4a29fb442eb75fb52f8eb64d20.1476.1615253999000000.xz

    ssize_t buflen, keylen, vallen;
    char exe_str[STR_LEN];
    char *buf, *key, *val;

    flb_info("[in_coredump][%s] full param : (%s)", __FUNCTION__, full);

    // Determine the length of the buffer needed.
    buflen = listxattr(full, NULL, 0);
    if (buflen == -1) {
        flb_error("[in_coredump][%s] failed listxattr", __FUNCTION__);
        return -1;
    }
    if (buflen == 0) {
        flb_error("[in_coredump][%s] no attributes", __FUNCTION__);
        return -1;
    }

    // Allocate the buffer.
    buf = malloc(buflen);
    if (buf == NULL) {
        flb_error("[in_coredump][%s] failed malloc", __FUNCTION__);
        return -1;
    }

    // Copy the list of attribute keys to the buffer
    buflen = listxattr(full, buf, buflen);
    flb_debug("[in_coredump][%s] buflen : (%d)", __FUNCTION__, buflen);

    if (buflen == -1) {
        return -1;
    } else if (buflen == 0) {
        flb_error("[in_coredump][%s] no attributes full : (%s)", __FUNCTION__, full);
        return -1;
    }

    key = buf;
    while (0 < buflen) {

        // Output attribute key
        flb_debug("[in_coredump][%s] key : (%s)", __FUNCTION__, key);

        // Determine length of the value
        vallen = getxattr(full, key, NULL, 0);

        if (vallen == -1) {
            flb_error("[in_coredump][%s] failed getxattr", __FUNCTION__);
        } else if (vallen == 0) {
            flb_error("[in_coredump][%s] no value", __FUNCTION__);
        } else {
            val = malloc(vallen + 1);
            if (val == NULL) {
                flb_error("[in_coredump][%s] failed malloc", __FUNCTION__);
                return -1;
            }

            // Copy value to buffer
            vallen = getxattr(full, key, val, vallen);
            if (vallen == -1) {
                flb_error("[in_coredump][%s] failed getxattr", __FUNCTION__);
            } else {
                // Check attribute value (exe, pid)
                val[vallen] = 0;
                flb_debug("[in_coredump][%s] val : (%s)", __FUNCTION__, val);
                
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

    strcpy(exe_str, exe);

    char *ptr = strtok(exe_str, "/");
    while (ptr != NULL)
    {
        flb_debug("[in_coredump][%s] ptr : (%s)", __FUNCTION__, ptr);
        if (strcmp(ptr, "usr") != 0 && strcmp(ptr, "bin") != 0 && strcmp(ptr, "sbin") != 0) {
            strcpy(comm, ptr);
            break;
        }
        ptr = strtok(NULL, "/");
    }

    return 0;
}

static int check_exe_time(const char *exe)
{
    flb_info("[in_coredump][%s] check exe (%s) file", __FUNCTION__, exe);

    struct stat exe_stat;

    struct tm *exe_tm_mtime;
    struct tm *exe_tm_ctime;

    struct time_information exe_time;

    if (lstat(exe, &exe_stat) == -1) {
        flb_error("[in_coredump][%s] Failed lstat (%s)", __FUNCTION__, exe);
        return -1;
    }

    exe_tm_mtime = localtime(&exe_stat.st_mtime);
    exe_tm_ctime = localtime(&exe_stat.st_ctime);
    flb_debug("[in_coredump][%s] Exe Modify time (%s), Change time (%s)", __FUNCTION__, ctime(&exe_stat.st_mtime), ctime(&exe_stat.st_ctime));
    flb_debug("[in_coredump][%s] Exe Modify time (%d %d %d), Change time (%d %d %d)", __FUNCTION__, exe_tm_mtime->tm_year + 1900, exe_tm_mtime->tm_mon + 1, exe_tm_mtime->tm_mday, exe_tm_ctime->tm_year + 1900, exe_tm_ctime->tm_mon + 1, exe_tm_ctime->tm_mday);

    exe_time.modify_year = exe_tm_mtime->tm_year + 1900;
    exe_time.modify_mon = exe_tm_mtime->tm_mon + 1;
    exe_time.modify_mday = exe_tm_mtime->tm_mday;
    exe_time.change_year = exe_tm_ctime->tm_year + 1900;
    exe_time.change_mon = exe_tm_ctime->tm_mon + 1;
    exe_time.change_mday = exe_tm_ctime->tm_mday;

    flb_info("[in_coredump][%s] Exe time information mtime (%d-%d-%d), ctime (%d-%d-%d)", __FUNCTION__, \
            exe_time.modify_year, exe_time.modify_mon, exe_time.modify_mday, \
            exe_time.change_year, exe_time.change_mon, exe_time.change_mday);

    if (default_time.modify_year != exe_time.modify_year || default_time.modify_mon != exe_time.modify_mon || default_time.modify_mday != exe_time.modify_mday || \
        default_time.change_year != exe_time.change_year || default_time.change_mon != exe_time.change_mon || default_time.change_mday != exe_time.change_mday)
        return -1;

    return 0;
}

static int create_crashreport(const char *script, const char *corefile, const char *crashreport)
{
    // corefile : core.coreexam_exampl.0.c7294e397ec747f98552c7c459f7dc1c.2434.1619053570000000.xz
    // crashreport : corefile-crashreport.txt
    // command : webos_capture.py --coredump corefile crashreport

    char command[STR_LEN];
    sprintf(command, "%s --coredump \'%s\' %s", script, corefile, crashreport);
    flb_info("[in_coredump][%s] command : %s", __FUNCTION__, command);

    int ret = system(command);

    return 0;
}

static int in_coredump_collect(struct flb_input_instance *ins, struct flb_config *config, void *in_context)
{
    int bytes = 0;
    int ret;
    struct flb_in_coredump_config *ctx = in_context;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    struct inotify_event *event;

    char full_path[STR_LEN];
    char comm[STR_LEN];
    char pid[STR_LEN];
    char exe[STR_LEN];
    char corefile[STR_LEN];
    char crashreport[STR_LEN];
    char upload_files[STR_LEN];
    char summary[STR_LEN];
    int len;
    char distro_result[STR_LEN];

    int cnt = 0;
    int i;

    if (init_default_time() == -1) {
        flb_error("[in_coredump][%s] Failed to initialize default time information", __FUNCTION__);
    }

    bytes = read(ctx->fd, ctx->buf + ctx->buf_len, sizeof(ctx->buf) - ctx->buf_len - 1);

    if (bytes <= 0) {
        flb_error("[in_coredump][%s] Failed to read data", __FUNCTION__);
        flb_input_collector_pause(ctx->coll_fd, ctx->ins);
        flb_engine_exit(config);
        return -1;
    }

    for (i=0; i < strlen(WEBOS_TARGET_DISTRO); i++) {
        if (*(WEBOS_TARGET_DISTRO+i) == '-')
            continue;

        distro_result[cnt++] = *(WEBOS_TARGET_DISTRO+i);
    }
    distro_result[cnt] = '\0';

    flb_info("[in_coredump][%s] modified distro from (%s) to (%s)", __FUNCTION__, WEBOS_TARGET_DISTRO, distro_result);

    ctx->buf_start = ctx->buf_len;
    ctx->buf_len += bytes;
    ctx->buf[ctx->buf_len] = '\0';

    flb_info("[in_coredump][%s] Catch the new coredump event", __FUNCTION__);

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    while (ctx->buf_start < ctx->buf_len) {
        event=(struct inotify_event*) &ctx->buf[ctx->buf_start];

        if (event->len == 0) {
            flb_error("[in_coredump][%s] event length is 0", __FUNCTION__);
            break;
        }

        if (!(event->mask & IN_CREATE)) {
            flb_error("[in_coredump][%s] not create event : %s", __FUNCTION__, event->name);
            break;
        }

        snprintf(full_path, STR_LEN, "%s/%s", ctx->path, event->name);
        flb_info("[in_coredump][%s] New file is created : (%s)", __FUNCTION__, full_path);
        strncpy(corefile, event->name, strlen(event->name));

        // Guarantee coredump file closing time
        sleep(1);

        if (verify_coredump_file(event->name) == -1) {
            flb_error("[in_coredump][%s] Not coredump file", __FUNCTION__);
            break;
        }

        if (parse_coredump_comm(full_path, comm, pid, exe) == -1) {
            flb_error("[in_coredump][%s] Fail to parse coredump file", __FUNCTION__);
            break;
        }
        flb_info("[in_coredump][%s] comm : (%s), pid : (%s), exe (%s)", __FUNCTION__, comm, pid, exe);

        if (check_exe_time(exe) == -1) {
            flb_error("[in_coredump][%s] Not official file", __FUNCTION__);
            break;
        }

        sprintf(crashreport, "%s/%s-crashreport.txt", PATH_COREDUMP_DIRECTORY, event->name);
        create_crashreport(ctx->crashreport_script, event->name, crashreport);

        if (access(crashreport, F_OK) != 0) {
            flb_error("[in_coredump][%s] failed to create crashreport : %s", __FUNCTION__, crashreport);
            break;
        }
        flb_info("[in_coredump][%s] crashreport file is created : %s)", __FUNCTION__, crashreport);

        // Guarantee crashreport file closing time
        sleep(1);

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
        flb_info("[in_coredump][%s] Add msgpack - key (%s) : val (%s)", __FUNCTION__, KEY_UPLOAD_FILES, upload_files);

        // key : summary | value : [RDX_CRASH][distro] comm
        msgpack_pack_str(&mp_pck, len=strlen(KEY_SUMMARY));
        msgpack_pack_str_body(&mp_pck, KEY_SUMMARY, len);

        snprintf(summary, STR_LEN, "[RDX_CRASH][%s] %s", distro_result, exe);
        msgpack_pack_str(&mp_pck, len=strlen(summary));
        msgpack_pack_str_body(&mp_pck, summary, len);
        flb_info("[in_coredump][%s] Add msgpack - key (%s) : val (%s)", __FUNCTION__, KEY_SUMMARY, summary);

        // flush to fluentbit
        flb_input_chunk_append_raw(ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);

        ctx->buf_start += EVENT_SIZE + event->len;
    }

    ctx->buf_len=ctx->buf_start=0;
    msgpack_sbuffer_destroy(&mp_sbuf);

    return 0;
}

static void in_coredump_config_destroy(struct flb_in_coredump_config *ctx)
{
    if (!ctx)
        return;

    flb_free(ctx);
}

/* Initialize plugin */
static int in_coredump_init(struct flb_input_instance *in, struct flb_config *config, void *data)
{
    int fd;
    int ret;
    struct flb_in_coredump_config *ctx;
    (void) data;

    const char *pval = NULL;

    /* Allocate space for the configuration */
    ctx = flb_malloc(sizeof(struct flb_in_coredump_config));
    if (!ctx)
        return -1;

    ctx->buf_len = 0;
    ctx->ins = in;

    fd = inotify_init();
    if (fd < 0) {
        flb_error("[in_coredump][%s] Failed to init inotify_init", __FUNCTION__);
        goto init_error;
    }

    ctx->fd = fd;
    ctx->buf_start=0;

    // Set the monitoring path for coredump file
    pval = flb_input_get_property("path", in);
    if (pval)
        ctx->path = (char *)pval;
    else
        ctx->path = PATH_COREDUMP_DIRECTORY;
    flb_info("[in_coredump][%s] Monitoring coredump file path : %s", __FUNCTION__, ctx->path);

    // Set the crashreport script
    pval = flb_input_get_property("script", in);
    if (pval)
        ctx->crashreport_script = pval;
    else
        ctx->crashreport_script = DEFAULT_SCRIPT;
    flb_info("[in_coredump][%s] Crashreport script : %s", __FUNCTION__, ctx->crashreport_script);

    // Always initialize built-in JSON pack state
    flb_pack_state_init(&ctx->pack_state);
    ctx->pack_state.multiple = FLB_TRUE;

    // Set watch descriptor
    ctx->wd = inotify_add_watch(ctx->fd, ctx->path, IN_CREATE);

    // Collect upon data available on the watch event
    ret = flb_input_set_collector_event(in, in_coredump_collect, ctx->fd, config);
    if (ret == -1) {
        flb_error("[in_coredump][%s] Failed to set collector_event", __FUNCTION__);
        goto init_error;
    }

    ctx->coll_fd = ret;

    // Set the context
    flb_input_set_context(in, ctx);

    flb_info("[in_coredump][%s] initialize done", __FUNCTION__);

    return 0;

init_error:
    in_coredump_config_destroy(ctx);
    return -1;
}

static int in_coredump_exit(void *in_context, struct flb_config *config)
{
    struct flb_in_coredump_config *ctx = in_context;

    if (!ctx)
        return 0;

    if (ctx->fd >= 0) {
        close(ctx->fd);
    }

    flb_pack_state_reset(&ctx->pack_state);
    in_coredump_config_destroy(ctx);

    return 0;
}

struct flb_input_plugin in_coredump_plugin = {
    .name         = "coredump",
    .description  = "Coredump Collector",
    .cb_init      = in_coredump_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_coredump_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_coredump_exit
};
