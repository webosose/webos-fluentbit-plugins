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

#include "webos_systemd.h"

#include "util/Logger.h"

extern int initWebOSSystemdFilter(struct flb_filter_instance *instance, struct flb_config *config, void *data);
extern int exitWebOSSystemdFilter(void *data, struct flb_config *config);
extern int filterWebOSSystemd(const void *data, size_t bytes, const char *tag, int tag_len, void **out_buf, size_t *out_size, struct flb_filter_instance *instance, void *context, struct flb_config *config);

static int cb_webos_systemd_init(struct flb_filter_instance *instance, struct flb_config *config, void *data)
{
    setLogContext(instance->log_level, instance->p->name);

    return initWebOSSystemdFilter(instance, config, data);
}

static int cb_webos_systemd_exit(void *data, struct flb_config *config)
{
    return exitWebOSSystemdFilter(data, config);
}

static int cb_webos_systemd_filter(const void *data, size_t bytes, const char *tag, int tag_len, void **out_buf, size_t *out_size, struct flb_filter_instance *instance, void *context, struct flb_config *config)
{
    return filterWebOSSystemd(data, bytes, tag, tag_len, out_buf, out_size, instance, context, config);
}

static char name[] = "webos_systemd";
static char description[] = "webos_systemd filter";
struct flb_filter_plugin filter_webos_systemd_plugin = {
    .name         = name,
    .description  = description,
    .cb_init      = cb_webos_systemd_init,
    .cb_filter    = cb_webos_systemd_filter,
    .cb_exit      = cb_webos_systemd_exit,
    .flags        = 0
};
