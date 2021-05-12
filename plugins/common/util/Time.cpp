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

#include "Time.h"

#include <time.h>
#include <chrono>

#include <boost/lexical_cast.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

bool operator <(const timespec& lhs, const timespec& rhs)
{
    if (lhs.tv_sec == rhs.tv_sec)
        return lhs.tv_nsec < rhs.tv_nsec;
    else
        return lhs.tv_sec < rhs.tv_sec;
}

Time::Time()
{
}

Time::~Time()
{
}

std::string Time::getCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    auto timenow = std::chrono::system_clock::to_time_t(now);

    std::string timeStr(30, '\0');
    std::strftime(&timeStr[0], timeStr.size(), "%Y-%m-%d %H:%M:%S", std::localtime(&timenow));

    std::string timeString;
    for (auto it = timeStr.begin(); it != timeStr.end(); ++it) {
        if (*it != '\0')
            timeString.push_back(*it);
    }
    return timeString;
}

string Time::generateUid()
{
    boost::uuids::uuid uid = boost::uuids::random_generator()();
    return string(boost::lexical_cast<string>(uid));
}

string Time::toISO8601(struct timespec* ts)
{
    static size_t BUFSIZE = 25;
    char buff[BUFSIZE];
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    if (!gmtime_r(&ts->tv_sec, &tm)) {
        return "";
    }
    size_t size = strftime(buff, sizeof(buff), "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(buff+size, BUFSIZE-size, ".%03ldZ", ts->tv_nsec/(1000*1000));
    return buff;
}
