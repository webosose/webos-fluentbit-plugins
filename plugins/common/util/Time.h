// Copyright (c) 2020 LG Electronics, Inc.
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

#ifndef UTIL_TIME_H_
#define UTIL_TIME_H_

#include <iostream>
#include <time.h>

using namespace std;

bool operator <(const timespec& lhs, const timespec& rhs);

class Time {
public:
    static std::string getCurrentTime(const char* format = "%Y-%m-%d %H:%M:%S");
    static string generateUid();
    static string toISO8601(struct timespec* ts);

    Time();
    virtual ~Time();
};

#endif /* UTIL_TIME_H_ */
