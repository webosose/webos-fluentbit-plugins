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

#include "util/PluginConf.h"

#include <algorithm>

#include "FluentBit.h"
#include "util/Logger.h"

list<pair<string, string>> PluginConf::EMPTY = list<pair<string, string>>();

PluginConf::PluginConf()
{
    setClassName("PluginConf");
}

PluginConf::~PluginConf()
{
}

void PluginConf::readConfFile(const char* path)
{
    PLUGIN_INFO("Conf path : %s", path);

    struct mk_rconf *fconf;
    struct mk_rconf_section *section;
    struct mk_rconf_entry *entry;
    struct mk_list *head;
    struct mk_list *head_e;

    // fconf = flb_config_static_open(path);
    if (NULL == (fconf = mk_rconf_open(path))) {
        PLUGIN_ERROR("Failed to read conf : %s", path);
        return;
    }

    mk_list_foreach(head, &fconf->sections) {
        section = mk_list_entry(head, struct mk_rconf_section, _head);
        string sectionName = section->name;
        PLUGIN_INFO("[%s]", sectionName.c_str());
        std::transform(sectionName.begin(), sectionName.end(), sectionName.begin(), ::toupper);
        m_configs[sectionName] = list<pair<string, string>>();

        mk_list_foreach(head_e, &section->entries) {
            entry = mk_list_entry(head_e, struct mk_rconf_entry, _head);
            PLUGIN_INFO("%s %s", entry->key, entry->val);
            m_configs[sectionName].emplace_back(make_pair(entry->key, entry->val));
        }
    }
    mk_rconf_free(fconf);
}

const list<pair<string, string>>& PluginConf::getSection(const string& section)
{
    string uppercaseSection = section;
    std::transform(uppercaseSection.begin(), uppercaseSection.end(), uppercaseSection.begin(), ::toupper);
    auto it = m_configs.find(uppercaseSection);
    if (it == m_configs.end())
        return EMPTY;
    return it->second;
}
