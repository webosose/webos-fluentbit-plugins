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
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <msgpack.h>
#include <sys/wait.h>

#include "jira.h"

#define KEY_SUMMARY             "summary"
#define KEY_UPLOAD_FILES        "upload-files"

#define DEFAULT_SCRIPT          "webos_issue.py"

#define STR_LEN                 1024

static struct json_object *get_typed_object(struct json_object *object, const char *key, json_type desired_type)
{
    struct json_object *obj = NULL;
    bool result = (json_object_object_get_ex(object, key, &obj)) && (json_object_get_type(obj) == desired_type);
    return result ? obj : NULL;
}

static bool get_json_string(struct json_object *object, const char *key, const char **value)
{
    bool result = false;
    struct json_object *strObj = get_typed_object(object, key, json_type_string);

    if (strObj) {
        *value = json_object_get_string(strObj);
        result = *value && strlen(*value) != 0;
    }

    return result;
}

static int cb_jira_init(struct flb_output_instance *ins, struct flb_config *config, void *data)
{
    int ret;
    const char *tmp;
    struct flb_out_jira_config *ctx = NULL;
    (void) ins;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_out_jira_config));
    if (!ctx) {
        flb_error("[out_jira][%s] failed to calloc", __FUNCTION__);
        return -1;
    }

    // Set format
    ctx->out_format = FLB_PACK_JSON_FORMAT_LINES;
    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        ret = flb_pack_to_json_format_type(tmp);
        if (ret == -1)
            flb_error("[out_jira][%s] unrecognized 'format' option", __FUNCTION__);
        else
            ctx->out_format = ret;
    }

    // Set date format
    ctx->json_date_format = FLB_PACK_JSON_DATE_DOUBLE;
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        ret = flb_pack_to_json_date_type(tmp);
        if (ret == -1)
            flb_error("[out_jira][%s] unrecognized 'json_date_format' option", __FUNCTION__);
        else
            ctx->json_date_format = ret;
    }

    // Set script
    tmp = flb_output_get_property("script", ins);
    if (tmp)
        ctx->jira_script = tmp;
    else
        ctx->jira_script = DEFAULT_SCRIPT;
    flb_info("[out_jira][%s] Jira script : %s", __FUNCTION__, ctx->jira_script);

    // Set date key
    tmp = flb_output_get_property("json_date_key", ins);
    if (tmp)
        ctx->json_date_key = flb_sds_create(tmp);
    else
        ctx->json_date_key = flb_sds_create("date");

    // Export context
    flb_output_set_context(ins, ctx);

    flb_info("[out_jira][%s] initialize done", __FUNCTION__);

    return 0;
}

static void cb_jira_flush(const void *data,
                          size_t bytes,
                          const char *tag,
                          int tag_len,
                          struct flb_input_instance *i_ins,
                          void *out_context,
                          struct flb_config *config)
{
    struct flb_out_jira_config *ctx = out_context;
    flb_sds_t json;

    struct json_object *object;
    char *summary;
    char *upload_files;
    char command[STR_LEN];

    json = flb_pack_msgpack_to_json_format(data, bytes, ctx->out_format, ctx->json_date_format, ctx->json_date_key);
    flb_debug("[out_jira][%s] %s", __FUNCTION__, json);

    object = json_tokener_parse(json);

    if (!get_json_string(object, KEY_SUMMARY, &summary)) {
        flb_error("[out_jira][%s] failed to get summary on (%s)", __FUNCTION__, object);
        return;
    }
    flb_info("[out_jira][%s] summary : %s", __FUNCTION__, summary);

    if (!get_json_string(object, KEY_UPLOAD_FILES, &upload_files)) {
        flb_error("[out_jira][%s] failed to get upload-files on (%s)", __FUNCTION__, object);
        return;
    }
    flb_info("[out_jira][%s] upload-files : %s", __FUNCTION__, upload_files);

    // template : command --summary XXX --unique-summary --upload-files YYY
    // example  : webos_issue.py --summary "[CRASH][OSE] bootd" --unique-summary --upload-files core.bootd.0.....xz

    sprintf(command, "%s --summary \'%s\' --unique-summary --upload-files %s", ctx->jira_script, summary, upload_files);
    flb_info("[out_jira][%s] command : %s", __FUNCTION__, command);

    int ret = system(command);

    FLB_OUTPUT_RETURN(FLB_OK);
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
    .description  = "Create JIRA",
    .cb_init      = cb_jira_init,
    .cb_flush     = cb_jira_flush,
    .cb_exit      = cb_jira_exit,
    .flags        = 0,
};
