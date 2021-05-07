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

#ifndef APPLAUNCHPERFLIST_H_
#define APPLAUNCHPERFLIST_H_

#include <list>
#include <map>
#include <memory>

#include "PerfRecord.h"

class PerfRecordList {
public:
    PerfRecordList(int timeout);
    virtual ~PerfRecordList();

    void add(shared_ptr<PerfRecord> item);
    shared_ptr<PerfRecord> get(const string& context);
    void remove(const string& context);
    void removeExpired(flb_time* baseTime);

    const list<shared_ptr<PerfRecord>>& getNoContextItems() const
    {
        return m_noContextItems;
    }

    const map<string, shared_ptr<PerfRecord>>& getContext2itemMap() const
    {
        return m_context2item;
    }

private:
    int m_timeout;
    list<shared_ptr<PerfRecord>> m_noContextItems;
    map<string, shared_ptr<PerfRecord>> m_context2item;
};

#endif
