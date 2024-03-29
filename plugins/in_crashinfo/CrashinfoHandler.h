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

#ifndef IN_CRASHINFOHANDLER_H_
#define IN_CRASHINFOHANDLER_H_

#include <string>
#include <sys/inotify.h>

#include "FluentBit.h"

#include "interface/IClassName.h"
#include "interface/ISingleton.h"

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

using namespace std;

/* COREDUMP Input configuration & context */
struct flb_in_coredump_config {
    int fd;                // coredump file descriptor
    int coll_fd;           // collector fd
    size_t buf_len;           // read buffer length
    size_t buf_start;         // read buffer length
    char buf[BUF_LEN];     // read buffer: 16Kb max

    // watch descriptor
    int wd;
    const char *path;

    // Parser / Format
    struct flb_pack_state pack_state;
    struct flb_input_instance *ins;

    const char *crashreport_script;
};

class InCrashinfoHandler : public IClassName {
public:
    static InCrashinfoHandler& getInstance();

    virtual ~InCrashinfoHandler();

    int onInit(struct flb_input_instance *ins, struct flb_config *config, void *data);
    int onExit(void *context, struct flb_config *config);
    int onCollect(struct flb_input_instance *ins, struct flb_config *config, void *context);

private:
    InCrashinfoHandler();
    InCrashinfoHandler(const InCrashinfoHandler&) = delete;
    InCrashinfoHandler& operator=(const InCrashinfoHandler&) = delete;

    void initDistroInfo();
    int verifyCoredumpFile(const char *corefile);
    int parseCoredumpComm(const string& coredump, string& comm, string& pid, string& exe);
    bool getCrashedFunction(const string& crashreport, const string& comm, string& func);
    void destroyCoredumpConfig(struct flb_in_coredump_config *ctx);

    string m_distro;
    string m_workDir;
    int m_maxEntries;
};

#endif
