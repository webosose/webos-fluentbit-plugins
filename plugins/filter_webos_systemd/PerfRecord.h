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

#ifndef PERFRECORD_H_
#define PERFRECORD_H_

#include <algorithm>
#include <list>
#include <string>

#ifdef __cplusplus
extern "C" {
#endif

#include <fluent-bit/flb_time.h>

#ifdef __cplusplus
}
#endif

using namespace std;

class PerfRecord {
public:
    PerfRecord() {}
    virtual ~PerfRecord() {}

    void addTimestamp(const string& state, flb_time time)
    {
        m_timestamps.push_back(make_pair(state, time));
    }

    void getLastTimestamp(flb_time** time)
    {
        *time = &m_timestamps.back().second;
    }

    bool getElapsedTime(const string& begin, const string& end, flb_time* diff)
    {
        flb_time* beginTime = &m_timestamps.front().second;
        flb_time* endTime = &m_timestamps.back().second;

        if (!begin.empty()) {
            auto it = std::find_if(m_timestamps.begin(), m_timestamps.end(), [&](auto& pair) { return begin == pair.first; });
            if (it == m_timestamps.end()) {
                return false;
            }
            beginTime = &it->second;
        }
        if (!end.empty()) {
            auto it = std::find_if(m_timestamps.begin(), m_timestamps.end(), [&](auto& pair) { return end == pair.first; });
            if (it == m_timestamps.end()) {
                return false;
            }
            endTime = &it->second;
        }

        if (-1 == flb_time_diff(endTime, beginTime, diff)) {
            return false;
        }
        return true;
    }

    void setContext(const string& context)
    {
        m_context = context;
    }

    const string& getContext() const
    {
        return m_context;
    }

private:
    list<pair<string, flb_time>> m_timestamps;
    string m_context;
};

#endif
