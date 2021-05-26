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

#include "jira.h"

#include <sys/wait.h>

#include "util/Logger.h"

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
    setLogContext(ins->log_level, ins->p->name);

    int ret;
    const char *tmp;
    struct flb_jira_config *ctx = NULL;
    (void) ins;
    (void) config;
    (void) data;

    ctx = flb_calloc(1, sizeof(struct flb_jira_config));
    if (!ctx) {
        PLUGIN_ERROR("failed to calloc");
        return -1;
    }

    // Set format
    ctx->out_format = FLB_PACK_JSON_FORMAT_LINES;
    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        ret = flb_pack_to_json_format_type(tmp);
        if (ret == -1)
            PLUGIN_ERROR("unrecognized 'format' option");
        else
            ctx->out_format = ret;
    }

    // Set date format
    ctx->json_date_format = FLB_PACK_JSON_DATE_DOUBLE;
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        ret = flb_pack_to_json_date_type(tmp);
        if (ret == -1)
            PLUGIN_ERROR("unrecognized 'json_date_format' option");
        else
            ctx->json_date_format = ret;
    }

    // Set script
    tmp = flb_output_get_property("script", ins);
    if (tmp)
        ctx->jira_script = tmp;
    else
        ctx->jira_script = DEFAULT_SCRIPT;
    PLUGIN_INFO("Jira script : %s", ctx->jira_script);

    // Set date key
    tmp = flb_output_get_property("json_date_key", ins);
    if (tmp)
        ctx->json_date_key = flb_sds_create(tmp);
    else
        ctx->json_date_key = flb_sds_create("date");

    // Export context
    flb_output_set_context(ins, ctx);

    PLUGIN_INFO("initialize done");

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
    struct flb_jira_config *ctx = out_context;
    flb_sds_t json;

    struct json_object *object;
    char *summary;
    char *upload_files;
    char command[STR_LEN];

    json = flb_pack_msgpack_to_json_format(data, bytes, ctx->out_format, ctx->json_date_format, ctx->json_date_key);
    PLUGIN_DEBUG("%s", json);

    object = json_tokener_parse(json);

    if (!get_json_string(object, KEY_SUMMARY, &summary)) {
        PLUGIN_ERROR("failed to get summary on (%s)", object);
        return;
    }
    PLUGIN_INFO("summary : %s", summary);

    if (!get_json_string(object, KEY_UPLOAD_FILES, &upload_files)) {
        PLUGIN_ERROR("failed to get upload-files on (%s)", object);
        return;
    }
    PLUGIN_INFO("upload-files : %s", upload_files);

    // template : command --summary XXX --unique-summary --upload-files YYY
    // example  : webos_issue.py --summary "[CRASH][OSE] bootd" --unique-summary --upload-files core.bootd.0.....xz

    sprintf(command, "%s --summary \'%s\' --unique-summary --upload-files %s", ctx->jira_script, summary, upload_files);
    PLUGIN_INFO("command : %s", command);

    int ret = system(command);

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_jira_exit(void *data, struct flb_config *config)
{
    struct flb_jira_config *ctx = data;

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
