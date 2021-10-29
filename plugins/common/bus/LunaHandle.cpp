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

#include "bus/LunaHandle.h"

#include "util/JValueUtil.h"
#include "util/Logger.h"

unsigned long LunaHandle::TIMEOUT = 5000;

void* LunaHandle::onThread(void *ctx)
{
    LunaHandle* self = (LunaHandle*)ctx;
    PLUGIN_INFO("Start to handle main context");
    g_main_loop_run(self->m_mainLoop);
    PLUGIN_INFO("End");
    return NULL;
}

LunaHandle::LunaHandle(const char* name)
    : LS::Handle(LS::registerService(name))
    , m_mainLoop(NULL)
    , m_thread(0)
    , m_queue(NULL)
{
    PLUGIN_INFO("%s", getName());
    setClassName("LunaHandle");
    m_mainLoop = g_main_loop_new(NULL, false);
}

LunaHandle::~LunaHandle()
{
    PLUGIN_INFO("%s", getName());
    g_main_loop_unref(m_mainLoop);
}

bool LunaHandle::initialize(rpa_queue_t *queue)
{
    PLUGIN_INFO("%s", getName());
    m_queue = queue;

    try {
        Handle::attachToLoop(m_mainLoop);
        PLUGIN_INFO("GMainLoop attached");
    } catch(exception& e) {
        PLUGIN_ERROR("Failed in attachToLoop: %s", e.what());
        return false;
    }
    int ret = pthread_create(&m_thread, NULL, onThread, this);
    if (ret != 0) {
        PLUGIN_ERROR("Failed in pthread_create: %d", ret);
        return false;
    }
    PLUGIN_INFO("pthread created");
    return true;
}

void LunaHandle::finalize()
{
    PLUGIN_INFO("%s", getName());
    try {
        Handle::detach();
    } catch (exception& ignore) {
    }
    g_main_loop_quit(m_mainLoop);
    int ret = pthread_join(m_thread, NULL);
    if (ret != 0) {
        PLUGIN_WARN("Failed in pthread_join: %d", ret);
    } else {
        PLUGIN_INFO("pthread joined");
    }
}
