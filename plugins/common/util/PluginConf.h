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

#ifndef UTIL_PLUGINCONF_H_
#define UTIL_PLUGINCONF_H_

#include <list>
#include <map>
#include <string>

#include "interface/IClassName.h"

using namespace std;

class PluginConf : public IClassName {
public:
    static list<pair<string, string>> EMPTY;

    static string token(string str);
    static string trim(string str);

    PluginConf();
    virtual ~PluginConf();

    void readConfFile(const char* path);

    const list<pair<string, string>>& getSection(const string& section);

private:
    // example.conf
    //
    // [INPUT]
    //     Path /usr/bin/xxx
    //     Path /usr/bin/yyy
    //
    // m_configs[SECTION] = list<pair<KEY, VALUE>>;
    map<string, list<pair<string, string>>> m_configs;

};

#endif
