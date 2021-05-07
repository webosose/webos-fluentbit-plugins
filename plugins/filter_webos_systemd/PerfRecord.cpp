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

#include "PerfRecord.h"

const int PerfRecord::STATE_BEGIN = INT_MIN;
const int PerfRecord::STATE_END = INT_MAX;

bool PerfRecord::getDiff(int startState, int endState, flb_time* diff)
{
    auto startTime = m_timestamps.find(startState);
    if (startTime == m_timestamps.end())
        return false;
    auto endTime = m_timestamps.find(endState);
    if (endTime == m_timestamps.end())
        return false;
    flb_time_diff(&endTime->second, &startTime->second, diff);
    return true;
}
