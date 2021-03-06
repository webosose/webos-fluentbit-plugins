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

#ifndef COREDUMPHANDLER_H_
#define COREDUMPHANDLER_H_

#include <list>
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
    unsigned int buf_len;           // read buffer length
    unsigned int buf_start;         // read buffer length
    char buf[BUF_LEN];     // read buffer: 16Kb max

    // watch descriptor
    int wd;
    char *path;

    // Parser / Format
    struct flb_pack_state pack_state;
    struct flb_input_instance *ins;

    const char *crashreport_script;
};

struct time_information
{
    int modify_year;
    int modify_mon;
    int modify_mday;

    int change_year;
    int change_mon;
    int change_mday;
};

class CoredumpHandler : public IClassName,
                        public ISingleton<CoredumpHandler> {
friend class ISingleton<CoredumpHandler>;
public:
    virtual ~CoredumpHandler();

    int onInit(struct flb_input_instance *ins, struct flb_config *config, void *data);
    int onExit(void *context, struct flb_config *config);
    int onCollect(struct flb_input_instance *ins, struct flb_config *config, void *context);

private:
    CoredumpHandler();

    int initDefaultTime();
    void initDistroInfo();
    int initOpkgChecksum();
    int verifyCoredumpFile(const char *corefile);
    int parseCoredumpComm(const char *full, char *comm, char *pid, char *exe);
    int checkOpkgChecksum();
    int checkExeTime(const char *exe);
    bool isExceptedExe(const char *exe);
    int createCrashreport(const char *script, const char *corefile, const char *crashreport);
    bool getCrashedFunction(const char* crashreport, char* func);
    void destroyCoredumpConfig(struct flb_in_coredump_config *ctx);

    struct time_information m_defaultTime;
    string m_distroResult;
    string m_officialChecksum;
    list<string> m_exceptions;
    bool m_isNFSMode;
};

#endif
