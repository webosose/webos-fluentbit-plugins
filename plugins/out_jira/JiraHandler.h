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

#ifndef JIRAHANDLER_H_
#define JIRAHANDLER_H_

#include <string>

#include "FluentBit.h"

#include "interface/IClassName.h"
#include "interface/ISingleton.h"

using namespace std;

class JiraHandler : public IClassName,
                    public ISingleton<JiraHandler> {
friend class ISingleton<JiraHandler>;
public:
    virtual ~JiraHandler();

    int onInit(struct flb_output_instance *ins, struct flb_config *config, void *data);
    int onExit(void *data, struct flb_config *config);
    void onFlush(const void *data, size_t bytes, const char *tag, int tag_len, struct flb_input_instance *ins, void *context, struct flb_config *config);

private:
    JiraHandler();

    int m_outFormat;
    int m_jsonDateFormat;
    flb_sds_t m_jsonDateKey;
    string m_jiraScript;
};

#endif
