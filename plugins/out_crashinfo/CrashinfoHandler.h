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

#ifndef CRASHINFOHANDLER_H_
#define CRASHINFOHANDLER_H_

#include <string>

#include "FluentBit.h"

#include "interface/IClassName.h"
#include "interface/ISingleton.h"

using namespace std;

class CrashinfoHandler : public IClassName,
                         public ISingleton<CrashinfoHandler> {
friend class ISingleton<CrashinfoHandler>;
public:
    virtual ~CrashinfoHandler();

    int onInit(struct flb_output_instance *ins, struct flb_config *config, void *data);
    int onExit(void *data, struct flb_config *config);
    void onFlush(const void *data, size_t bytes, const char *tag, int tag_len, struct flb_input_instance *ins, void *context, struct flb_config *config);

private:
    CrashinfoHandler();

    string m_workDir;
    int m_maxEntries;
};

#endif
