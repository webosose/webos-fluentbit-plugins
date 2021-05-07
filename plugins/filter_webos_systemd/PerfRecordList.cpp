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

#include "PerfRecordList.h"

PerfRecordList::PerfRecordList(int timeout)
    : m_timeout(timeout)
{
}

PerfRecordList::~PerfRecordList()
{
}

void PerfRecordList::add(shared_ptr<PerfRecord> item)
{
    if (item->getContext().empty()) {
        m_noContextItems.emplace_back(item);
        return;
    }
    m_context2item[item->getContext()] = item;
}

 shared_ptr<PerfRecord> PerfRecordList::get(const string& context)
 {
     auto it = m_context2item.find(context);
     if (it != m_context2item.end()) {
         return it->second;
     }
     // cannot find with context : search from no-contextItems.
     if (m_noContextItems.empty()) {
         return nullptr;
     }
     shared_ptr<PerfRecord> item = m_noContextItems.back();
     m_noContextItems.remove(item);
     m_context2item[context] = item;
     return item;
 }

 void PerfRecordList::remove(const string& context)
 {
     auto it = m_context2item.find(context);
     if (it != m_context2item.end()) {
         m_context2item.erase(it);
     }
}

 void PerfRecordList::removeExpired(flb_time* baseTime)
 {
     flb_time diff;
     flb_time* lastTimestamp;
     for (auto it = m_noContextItems.begin(); it != m_noContextItems.end(); ) {
         (*it)->getLastTimestamp(&lastTimestamp);
         flb_time_diff(baseTime, lastTimestamp, &diff);
         if (diff.tm.tv_sec < m_timeout) {
             ++it;
             continue;
         }
         it = m_noContextItems.erase(it);
     }
     for (auto it = m_context2item.begin(); it != m_context2item.end(); ) {
         it->second->getLastTimestamp(&lastTimestamp);
         flb_time_diff(baseTime, lastTimestamp, &diff);
         if (diff.tm.tv_sec < m_timeout) {
             ++it;
             continue;
         }
         it = m_context2item.erase(it);
     }
 }
