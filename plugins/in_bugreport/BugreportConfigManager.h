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

#ifndef BUGREPORTCONFIGMANAGER_H_
#define BUGREPORTCONFIGMANAGER_H_

#include <list>
#include <string>
#include <pbnjson.hpp>

#include "FluentBit.h"
#include "bus/LunaHandle.h"
#include "interface/IClassName.h"
#include "interface/ISingleton.h"
#include "util/ErrCode.h"

using namespace std;
using namespace pbnjson;

class BugreportConfigManager : public IClassName {
public:
    BugreportConfigManager();
    virtual ~BugreportConfigManager();

    bool initialize();
    bool finalize();

    JValue getConfig();
    ErrCode setAccount(JValue& account);

    string getUsername() const;
    string getPassword() const;
    string getSummary() const;
    string getDescription() const;

private:
    JValue m_config;
};

#endif
