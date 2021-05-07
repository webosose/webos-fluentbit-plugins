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

#include <map>

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
    static const int STATE_BEGIN;
    static const int STATE_END;

    PerfRecord() {}
    virtual ~PerfRecord() {}

    bool getDiff(int startState, int endState, flb_time* diff);

    void addTimestamp(int state, flb_time time)
    {
        m_timestamps[state] = time;
    }

    const map<int, flb_time>& getTimestamps() const
    {
        return m_timestamps;
    }

    void getLastTimestamp(flb_time** time)
    {
        *time = &m_timestamps.rbegin()->second;
    }

    bool getTotalTime(flb_time* total)
    {
        return getDiff(STATE_BEGIN, STATE_END, total);
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
    map<int, flb_time> m_timestamps;
    string m_context;
};

#endif
