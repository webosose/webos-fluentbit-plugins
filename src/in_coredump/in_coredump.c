/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

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

//#include "Environment.h"
#include "in_coredump.h"

#define COREDUMP_PATH "/var/lib/systemd/coredump"
#define COMPONENT_KEY "component"
#define PID_KEY		  "pid"

#define UPLOAD_FILE_KEY "upload-files"
#define SUMMARY_KEY		  "summary"
#define SUMMARY_MAX    10240

static int in_coredump_collect(struct flb_input_instance *i_ins,
                            struct flb_config *config, void *in_context)
{
    int bytes = 0;
    int pack_size;
    int ret;
    char *pack;
    struct flb_in_coredump_config *ctx = in_context;
    msgpack_packer mp_pck;
    msgpack_sbuffer mp_sbuf;

    flb_debug("[in_coredump] wait for inotify events  ");
    bytes = read(ctx->fd,
                 ctx->buf + ctx->buf_len,
                 sizeof(ctx->buf) - ctx->buf_len - 1);
   
    flb_debug("[in_coredump] some inotify events  ");
    if (bytes == 0) {
        flb_warn("[in_coredump] end of file (coredump closed by remote end)");
    }
    if (bytes <= 0) {
        flb_input_collector_pause(ctx->coll_fd, ctx->i_in);
        flb_engine_exit(config);
        return -1;
    }
    flb_debug("[in_coredump] some filed changed  ");
    ctx->buf_start = ctx->buf_len;
    ctx->buf_len += bytes;
    ctx->buf[ctx->buf_len] = '\0';

    /* Initialize local msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    while (ctx->buf_len > ctx->buf_start) {
       struct inotify_event *event=(struct inotify_event*) &ctx->buf[ctx->buf_start];
       if (event->len) {
           if ((event->mask & IN_CREATE) && !(event->mask & IN_ISDIR) ) {
               char *result;
               char component_name[PATH_MAX];
               char upload_files[PATH_MAX];
               char summary[SUMMARY_MAX];
               char pid[PATH_MAX];
               struct flb_time tm;
               int len;

               flb_debug("[in_coredump] File %s was created!!", event->name);

               // filename  core.coreexam.0.5999de4a29fb442eb75fb52f8eb64d20.1476.1615253999000000.xz
               result=strtok(event->name, ".");

               snprintf(upload_files, PATH_MAX, "%s/%s", ctx->path, event->name)
               snprintf(component_name, PATH_MAX, "%s", result);

               if (strcmp(component_name, "core") == 0) {
                   while(result != NULL) {  //remain coreexam.0.5999de4a29fb442eb75fb52f8eb64d20.1476.1615253999000000.xz
                       // key - value
                       // component name -> token1
                       // process id -> token2
                       result=strtok(NULL,".");
                       if (result != NULL)  { //component name, remain 0.5999de4a29fb442eb75fb52f8eb64d20.1476.1615253999000000.xz
						   strcpy(component_name,result);
                          
                           result=strtok(NULL, ".");
                           if (result != NULL) { // unknown 0, remain 5999de4a29fb442eb75fb52f8eb64d20.1476.1615253999000000.xz
                               result=strtok(NULL, ".");
                               if (result != NULL) { // unkown 5999de4a29fb442eb75fb52f8eb64d20, remain 1476.1615253999000000.xz
                                   result = strtok(NULL, ".");
                                   if (result != NULL) { // pid 1476 remain 1615253999000000.xz
                                       strcpy(pid, result);
                                       msgpack_pack_array(&mp_pck, 2); // 2-> time / json value 
                                       flb_pack_time_now(&mp_pck);

                                       /* component key, pid */
                                       msgpack_pack_map(&mp_pck, 2); 

#if 0
                                       /* key - component name */
                                       msgpack_pack_str(&mp_pck,len=strlen(COMPONENT_KEY));
                                       msgpack_pack_str_body(&mp_pck, COMPONENT_KEY, len);
                                       flb_debug("[in_coredump] %s len %d was created!!", COMPONENT_KEY, len);

                                       /* value - component name */
                                       msgpack_pack_str(&mp_pck,len=strlen(component_name));
                                       msgpack_pack_str_body(&mp_pck, component_name, len);
                                       flb_debug("[in_coredump] compoent_name %s len %d was created!!", component_name, len);

                                       /* key - process id */
                                       msgpack_pack_str(&mp_pck,len=strlen(PID_KEY));
                                       msgpack_pack_str_body(&mp_pck, PID_KEY, len);
                                       flb_debug("[in_coredump] pid %s len %d was created!!", PID_KEY, len);

                                       /* value - process id */
                                       msgpack_pack_str(&mp_pck,len=strlen(pid));
                                       msgpack_pack_str_body(&mp_pck, pid, len);
                                       flb_debug("[in_coredump] pid %s len %d was created!!", pid, len);
#else
                                       /* key - upload-files */
                                       msgpack_pack_str(&mp_pck, len=strlen(UPLOAD_FILE_KEY)
                                       msgpack_pack_str_body(&mp_pck, UPLOAD_FILE_KEY, len);

                                       /* value - path */
                                       //msgpack_array(&mp_pck, 1); 
                                       msgpack_pack_str(&mp_pck, len=strlen(upload_files));
                                       msgpack_pack_str_body(&mp_pck, upload_files, len);
                                       flb_debug("[in_coredump] %s len %d was created!!", UPLOAD_FILE_KEY, len);

                                       /* key - summary */
                                       msgpack_pack_str(&mp_pck, len=strlen(SUMMARY_KEY));
                                       msgpack_pack_str_body(&mp_pck, SUMMARY_KEY, len);

                                       /* value - [CRASH] name */
                                       snprintf(summary, SUMMARY_MAX, "[CRASH] %s_%s", WEBOS_TARGET_DISTRO, component_name)

                                       msgpack_pack_str(&mp_pck, len=strlen(summary));
                                       msgpack_pack_str_body(&mp_pck, summary, len);
                                       flb_debug("[in_coredump] %s len %d value was created!!", summary, len);

#endif
                                       /* flush to fluentbit */
                                       flb_input_chunk_append_raw(i_ins, NULL, 0, mp_sbuf.data, mp_sbuf.size);
                                   } else {
                                       flb_warn("[in_coredump] It wasn't coredump file\n");
                                   }
                               } else {
                                   flb_warn("[in_coredump] It wasn't coredump file\n");
                               }
                           } else {
                               flb_warn("[in_coredump] It wasn't coredump file\n");
                           }
                       } else {
                           flb_warn("[in_coredump] It wasn't coredump file\n");
                       } 
                   }
               } else {
                  flb_warn("[in_coredump] It wasn't coredump file\n");
               }
           } else {
               // no file creation(another event)
               flb_warn("[in_coredump] file %s: it was not created event!!", event->name);
           }
       }
       ctx->buf_start += EVENT_SIZE + event->len;
       
    }
	ctx->buf_len=ctx->buf_start=0;
    msgpack_sbuffer_destroy(&mp_sbuf);
   
    return 0;
}

/* Initialize plugin */
static int in_coredump_init(struct flb_input_instance *in,
                         struct flb_config *config, void *data)
{
    int fd;
    int ret;
    const char *tmp;
    struct flb_in_coredump_config *ctx;
    (void) data;

    /* Allocate space for the configuration */
    ctx = flb_malloc(sizeof(struct flb_in_coredump_config));
    if (!ctx) {
        return -1;
    }
    ctx->buf_len = 0;
    ctx->i_in = in;

    fd = inotify_init();
    if ( fd < 0 ) {
        flb_error("[in_coredump] can't do inotify_init");
    }
    ctx->fd = fd;
    ctx->buf_start=0;

    /* Config: path/pattern to read files */
    tmp = flb_input_get_property("path", in);
    if (tmp) {
        ctx->path = tmp;
        flb_debug("[in_coredump] requested monitoring path '%s' ", tmp);
    }
    else {
        ctx->path = COREDUMP_PATH;
    }
    /* Always initialize built-in JSON pack state */
    flb_pack_state_init(&ctx->pack_state);
    ctx->pack_state.multiple = FLB_TRUE;

    /* Set the context */
    flb_input_set_context(in, ctx);

    flb_debug("[in_coredump] requested monitoring path '%s' ", ctx->path);
    ctx->wd = inotify_add_watch( ctx->fd, ctx->path, IN_CREATE );

    flb_debug("[in_coredump] initialize ");
    /* Collect upon data available on the standard input */
    ret = flb_input_set_collector_event(in,
                                        in_coredump_collect,
                                        ctx->fd,
                                        config);
    if (ret == -1) {
        flb_error("[in_coredump] Could not set collector for COREDUMP input plugin");
        flb_free(ctx);
        return -1;
    }
    ctx->coll_fd = ret;

    return 0;
}

/* Cleanup serial input */
static int in_coredump_exit(void *in_context, struct flb_config *config)
{
    struct flb_in_coredump_config *ctx = in_context;

    if (ctx->fd >= 0) {
        close(ctx->fd);
    }
    flb_pack_state_reset(&ctx->pack_state);
    flb_free(ctx);

    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_coredump_plugin = {
    .name         = "coredump",
    .description  = "Coredump Collector",
    .cb_init      = in_coredump_init,
    .cb_pre_run   = NULL,
    .cb_collect   = in_coredump_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = in_coredump_exit
};
