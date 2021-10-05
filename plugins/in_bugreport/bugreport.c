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

#include "util/Logger.h"

extern int initBugreportHandler(struct flb_input_instance *ins, struct flb_config *config, void *data);
extern int exitBugreportHandler(void *context, struct flb_config *config);
extern int collectBugreport(struct flb_input_instance *ins, struct flb_config *config, void *context);

static int bugreport_init(struct flb_input_instance *ins, struct flb_config *config, void *data)
{
    setLogContext(ins->log_level, ins->p->name);

    return initBugreportHandler(ins, config, data);
}

static int bugreport_exit(void *context, struct flb_config *config)
{
    return exitBugreportHandler(context, config);
}

static int bugreport_collect(struct flb_input_instance *ins, struct flb_config *config, void *context)
{
    return collectBugreport(ins, config, context);
}

static int bugreport_prerun(struct flb_input_instance *ins, struct flb_config *config, void *context)
{
    PLUGIN_INFO();
    return 0;
}

/* Plugin reference */
struct flb_input_plugin in_bugreport_plugin = {
    .name = "bugreport",
    .description = "Collect information for bugreport",
    .cb_init = bugreport_init,
    .cb_pre_run = bugreport_prerun,
    .cb_collect = bugreport_collect,
    .cb_flush_buf = NULL,
    .cb_pause = NULL,
    .cb_resume = NULL,
    .cb_exit = bugreport_exit
};
