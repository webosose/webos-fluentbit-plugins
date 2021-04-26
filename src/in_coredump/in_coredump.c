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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/inotify.h>
#include <limits.h>

#include "in_coredump.h"

#define PATH_COREDUMP_DIRECTORY "/var/lib/systemd/coredump"

#define DEFAULT_SCRIPT          "webos_capture.py"

#define KEY_SUMMARY		        "summary"
#define KEY_UPLOAD_FILES        "upload-files"

#define STR_LEN                 1024

static int parse_coredump_comm(const char *full, const char *comm, const char *pid)
{
    // template : core string | comm | uid | boot id | pid | timestamp
    // example  : core.coreexam.0.5999de4a29fb442eb75fb52f8eb64d20.1476.1615253999000000.xz

    int cnt = 0;
    char *ptr = strtok(full, ".");

    if (strncmp(full, "core", 4) != 0) {
        flb_error("[in_coredump][%s] Not coredump file : %s", __FUNCTION__, full);
        return -1;
    }

    while (ptr != NULL)
    {
        if (cnt == 1) {
            strncpy(comm, ptr, strlen(ptr)+1);
        } else if (cnt == 4) {
            strncpy(pid, ptr, strlen(ptr)+1);
            break;
        }

        ptr = strtok(NULL, ".");
        cnt++;
    }

    return 0;
}

static int create_crashreport(const char *script, const char *file, const char *crashreport)
{
    // file : /var/lib/systemd/coredump/core.coreexam_ose.0.c7294e397ec747f98552c7c459f7dc1c.2434.1619053570000000.xz
    // crashreport : /var/log/crashreport_comm.pid.log
    // command : webos_capture.py --coredump file crashreport

    char command[STR_LEN];
    sprintf(command, "%s --coredump %s %s", script, file, crashreport);
    flb_info("[in_coredump][%s] command : %s", __FUNCTION__, command);

    system(command);

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
    char corefile[STR_LEN];
    char crashreport[STR_LEN];
    char upload_files[STR_LEN];
    char summary[STR_LEN];
    int len;
    char distro_result[STR_LEN];

    int cnt = 0;
    int i;

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
        flb_info("[in_coredump][%s] coredump file is created : (%s)", __FUNCTION__, full_path);
        strncpy(corefile, event->name, strlen(event->name));

        parse_coredump_comm(event->name, comm, pid);
        flb_debug("[in_coredump][%s] comm : %s, pid : %s", __FUNCTION__, comm, pid);

        sprintf(crashreport, "/var/log/crashreport_%s.%s.log", comm, pid);
        create_crashreport(ctx->crashreport_script, corefile, crashreport);

        if (access(crashreport, F_OK) != 0) {
            flb_error("[in_coredump][%s] failed to create crashreport : %s", __FUNCTION__, crashreport);
            break;
        }
        flb_info("[in_coredump][%s] crashreport file is created : %s)", __FUNCTION__, crashreport);

        snprintf(upload_files, STR_LEN, "%s %s", full_path, crashreport);

        // Wait closeing time for coredump file
        sleep(1);

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

        snprintf(summary, STR_LEN, "[RDX_CRASH][%s] %s", WEBOS_TARGET_DISTRO, comm);
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
        ctx->path = pval;
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
