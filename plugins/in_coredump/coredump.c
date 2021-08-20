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

#include "coredump.h"

#include "util/Logger.h"

extern int initCoredumpHandler(struct flb_input_instance *in, struct flb_config *config, void *data);
extern int exitCoredumpHandler(void *in_context, struct flb_config *config);
extern int collectCoredump(struct flb_input_instance *ins, struct flb_config *config, void *in_context);

static int coredump_init(struct flb_input_instance *ins, struct flb_config *config, void *data)
{
    setLogContext(ins->log_level, ins->p->name);

    return initCoredumpHandler(ins, config, data);
}

static int coredump_exit(void *context, struct flb_config *config)
{
    return exitCoredumpHandler(context, config);
}

static int coredump_collect(struct flb_input_instance *ins, struct flb_config *config, void *context)
{
    return collectCoredump(ins, config, context);
}

struct flb_input_plugin in_coredump_plugin = {
    .name         = "coredump",
    .description  = "Coredump Collector",
    .cb_init      = coredump_init,
    .cb_pre_run   = NULL,
    .cb_collect   = coredump_collect,
    .cb_flush_buf = NULL,
    .cb_exit      = coredump_exit
};
