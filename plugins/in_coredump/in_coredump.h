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

#ifndef FLB_IN_COREDUMP_H
#define FLB_IN_COREDUMP_H

#include <sys/inotify.h>

#include "Environment.h"
#include "FluentBit.h"

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

/* COREDUMP Input configuration & context */
struct flb_in_coredump_config {
    int fd;                // coredump file descriptor
    int coll_fd;           // collector fd
    int buf_len;           // read buffer length
    int buf_start;         // read buffer length
    char buf[BUF_LEN];     // read buffer: 16Kb max

    // watch descriptor
    int wd;
    char *path;

    // Parser / Format
    struct flb_pack_state pack_state;
    struct flb_input_instance *ins;

    const char *crashreport_script;
};

extern struct flb_input_plugin in_coredump_plugin;

#endif
