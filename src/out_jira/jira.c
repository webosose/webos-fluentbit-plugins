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
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>
#include <sys/wait.h>

#include "jira.h"


//#define HANDLE_NEWCHILD //it works
#define JIRA_DEFAULT_SCRIPTS "/etc/fluent-bit/mypython.py"
#define JIRA_RUN_PYTHON  "/usr/bin/python3"

static int cb_jira_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    int ret;
    char *tmp;
    struct flb_out_jira_config *ctx = NULL;
    (void) ins;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_out_jira_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ctx->out_format = FLB_PACK_JSON_FORMAT_LINES; //json lines is default
    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        ret = flb_pack_to_json_format_type(tmp);
        if (ret == -1) {
            flb_error("[out_jira] unrecognized 'format' option. "
                      "Using 'msgpack'");
        }
        else {
            ctx->out_format = ret;
        }
    }

    /* Date format for JSON output */
    ctx->json_date_format = FLB_PACK_JSON_DATE_DOUBLE;
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        ret = flb_pack_to_json_date_type(tmp);
        if (ret == -1) {
            flb_error("[out_jira] invalid json_date_format '%s'. "
                      "Using 'double' type");
        }
        else {
            ctx->json_date_format = ret;
        }
    }

    /* path to python script */
    tmp = flb_output_get_property("script", ins);
    if (tmp) {
        ctx->script = tmp;
        flb_debug("[out_jira] python script path '%s' ", tmp);
    }
    else {
        ctx->script = JIRA_DEFAULT_SCRIPTS;
    }


    /* Date key for JSON output */
    tmp = flb_output_get_property("json_date_key", ins);
    if (tmp) {
        ctx->json_date_key = flb_sds_create(tmp);
    }
    else {
        ctx->json_date_key = flb_sds_create("date");
    }

    /* Export context */
    flb_output_set_context(ins, ctx);

    return 0;
}

static void cb_jira_flush(const void *data, size_t bytes,
                            const char *tag, int tag_len,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    msgpack_unpacked result;
    size_t off = 0, cnt = 0;
    struct flb_out_jira_config *ctx = out_context;
    flb_sds_t json;
    char *buf = NULL;
    (void) i_ins;
    (void) config;
    struct flb_time tmp;
    msgpack_object *p;

    FILE *fw;
    pid_t pid_child_python, pid_child_topy;
    int fd[2];
    int status;

    if(pipe(fd)==-1){
        flb_error("pipe error..\n");
    }

    pid_child_python = fork();

    if (pid_child_python == -1) {
        flb_error("[out_jira]:can't fork python task\n");
    } else if (pid_child_python == 0) {
        // python child
        // close ununsed pipe
        dup2(fd[0],STDIN_FILENO);
        close(fd[1]);

        execl(JIRA_RUN_PYTHON, JIRA_RUN_PYTHON, ctx->script, NULL);        
        exit(1);
    } else { // parent
#ifdef HANDLE_NEWCHILD
       pid_child_topy = fork(); 
       if (pid_child_topy == -1) {
            flb_error("[out_jira]:fork failed:python interpreter\n");
       } else if (pid_child_topy == 0) { // child will send data to python 
#endif
            // close the unused pipe
	        close(fd[0]); 
#ifdef HANDLE_NEWCHILD
		    dup2(fd[1],STDOUT_FILENO);
#endif
#ifndef HANDLE_NEWCHILD
            if((fw=fdopen(fd[1], "w")) == NULL) {
                  flb_error("[out_jira]:fork failed:python interpreter\n");
                  close(fd[1]);
                  FLB_OUTPUT_RETURN(FLB_RETRY);
            }
#endif

            if (ctx->out_format != FLB_PACK_JSON_FORMAT_NONE) {
                json = flb_pack_msgpack_to_json_format(data, bytes,
													   ctx->out_format,
													   ctx->json_date_format,
													   ctx->json_date_key);
#ifdef HANDLE_NEWCHILD
                 write(STDOUT_FILENO, json, flb_sds_len(json));
#else
                 write(fd[1], json, flb_sds_len(json));
#endif
                 flb_sds_destroy(json);
                 /*
                  * If we are 'not' in json_lines mode, we need to add an extra
                  * breakline.
                  */
                  if (ctx->out_format != FLB_PACK_JSON_FORMAT_LINES) {
                       dprintf(fd[1], "\n");
		          }
		    	  flb_debug("[out_jira] out format %d\n", ctx->out_format);
#ifdef HANDLE_NEWCHILD
                  fflush(stdout);
#endif
            } else { 
                  /* A tag might not contain a NULL byte */
                  buf = flb_malloc(tag_len + 1);
                  if (!buf) {
                       flb_errno();
#ifdef HANDLE_NEWCHILD
                       //FLB_OUTPUT_RETURN(FLB_RETRY);
                       flb_output_return_do(FLB_RETRY);
		    	       flb_debug("[out_jira] tag is NULL\n");
                       exit(0);
#else
                       close(fd[1]);
                       FLB_OUTPUT_RETURN(FLB_RETRY);
#endif
	              }
	    		  /*
                   * If we are 'not' in json_lines mode, we need to add an extra
                   * breakline.
                   */
#if 0
                  if (ctx->out_format != FLB_PACK_JSON_FORMAT_LINES) {
                       printf("\n");
                  }
#endif
                  memcpy(buf, tag, tag_len);
                  buf[tag_len] = '\0';
                  msgpack_unpacked_init(&result);

                  while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
#ifdef HANDLE_NEWCHILD
                       printf("[%zd] %s: [", cnt++, buf);
                       flb_time_pop_from_msgpack(&tmp, &result, &p);
                       printf("%"PRIu32".%09lu, ", (uint32_t)tmp.tm.tv_sec, tmp.tm.tv_nsec);

				       msgpack_object_print(stdout, *p);
                       printf("]\n");
#else
                       fprintf(fw,"[%zd] %s: [", cnt++, buf);
                       flb_time_pop_from_msgpack(&tmp, &result, &p);
                       fprintf(fw,"%"PRIu32".%09lu, ", (uint32_t)tmp.tm.tv_sec, tmp.tm.tv_nsec);

				       msgpack_object_print(fw, *p);
                       fprintf(fw,"]\n");
#endif
                  }
                  msgpack_unpacked_destroy(&result);
                  flb_free(buf);
            }
#ifdef HANDLE_NEWCHILD
            fflush(stdout);
            close(stdout);
            exit(0);
#else
            fclose(fw);
            close(fd[1]);
            waitpid(pid_child_python, &status,0);
            FLB_OUTPUT_RETURN(FLB_OK);
#endif
#ifdef HANDLE_NEWCHILD
        } else { //parent
	        close(fd[0]); 
		    close(fd[1]);
            waitpid(pid_child_topy, &status,0);
            waitpid(pid_child_python, &status,0);
            FLB_OUTPUT_RETURN(FLB_OK);
        }
#endif
    }
}

static int cb_jira_exit(void *data, struct flb_config *config)
{
    struct flb_out_jira_config *ctx = data;

    if (!ctx) {
        return 0;
    }
    if (ctx->json_date_key) {
        flb_sds_destroy(ctx->json_date_key);
    }

    flb_free(ctx);
    return 0;
}

struct flb_output_plugin out_jira_plugin = {
    .name         = "jira",
    .description  = "Prints events to JIRA",
    .cb_init      = cb_jira_init,
    .cb_flush     = cb_jira_flush,
    .cb_exit      = cb_jira_exit,
    .flags        = 0,
};
