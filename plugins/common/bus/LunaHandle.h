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

#ifndef BUS_LUNAHANDLE_H
#define BUS_LUNAHANDLE_H

#include <iostream>
#include <pthread.h>

#include <luna-service2/lunaservice.hpp>
#include <pbnjson.hpp>

#include "external/rpa_queue.h"
#include "interface/ISingleton.h"
#include "interface/IClassName.h"

using namespace LS;
using namespace std;
using namespace pbnjson;

class LSErrorSafe : public LSError {
public:
    LSErrorSafe()
    {
        LSErrorInit(this);
    }

    ~LSErrorSafe()
    {
        LSErrorFree(this);
    }
};

class LunaHandle : public LS::Handle,
                   public IClassName {
public:
    LunaHandle(const char* name);
    virtual ~LunaHandle();

    bool initialize(rpa_queue_t* queue = NULL);
    void finalize(void);
    void onThread(void);

    static unsigned long TIMEOUT;

private:
    GMainLoop* m_mainLoop = NULL;
    pthread_t m_thread;
    rpa_queue_t* m_queue;
};

#endif
