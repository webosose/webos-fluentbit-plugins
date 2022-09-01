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

#include "crashinfo.h"

#include "util/Logger.h"

extern int initInCrashinfoHandler(struct flb_input_instance *in, struct flb_config *config, void *data);
extern int exitInCrashinfoHandler(void *in_context, struct flb_config *config);
extern int collectInCrashinfo(struct flb_input_instance *ins, struct flb_config *config, void *in_context);

static int crashinfo_init(struct flb_input_instance *ins, struct flb_config *config, void *data)
{
    setLogContext(ins->log_level, ins->p->description);

    return initInCrashinfoHandler(ins, config, data);
}

static int crashinfo_exit(void *context, struct flb_config *config)
{
    return exitInCrashinfoHandler(context, config);
}

static int crashinfo_collect(struct flb_input_instance *ins, struct flb_config *config, void *context)
{
    return collectInCrashinfo(ins, config, context);
}

struct flb_input_plugin in_crashinfo_plugin = {
    .name         = "crashinfo",
    .description  = "crashinfo.in",
    .cb_init      = crashinfo_init,
    .cb_pre_run   = NULL,
    .cb_collect   = crashinfo_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = crashinfo_exit
};
