// Copyright (c) 2022 LG Electronics, Inc.
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

#include "crashinfo.h"

#include "util/Logger.h"

static int cb_crashinfo_init(struct flb_output_instance *ins, struct flb_config *config, void *data)
{
    setLogContext(ins->log_level, ins->p->description);

    return initOutCrashinfoHandler(ins, config, data);
}

static void cb_crashinfo_flush(const void *data, size_t bytes, const char *tag, int tag_len, struct flb_input_instance *ins, void *context, struct flb_config *config)
{
    flushOutCrashinfo(data, bytes, tag, tag_len, ins, context, config);
}

static int cb_crashinfo_exit(void *data, struct flb_config *config)
{
    return exitOutCrashinfoHandler(data, config);
}

char name[] = "crashinfo";
char description[] = "crashinfo.out";
struct flb_output_plugin out_crashinfo_plugin = {
    .name         = name,
    .description  = description,
    .cb_init      = cb_crashinfo_init,
    .cb_flush     = cb_crashinfo_flush,
    .cb_exit      = cb_crashinfo_exit,
    .flags        = 0,
};
