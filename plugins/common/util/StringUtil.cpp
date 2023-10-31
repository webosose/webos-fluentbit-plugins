// Copyright (c) 2023 LG Electronics, Inc.
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

#include <cstdint>
#include "StringUtil.h"

string StringUtil::trim(const string& str, const char* t)
{
    return ltrim(rtrim(str, t), t);
}

string StringUtil::ltrim(const string& str, const char* t)
{
    string s(str);
    if (t) {
        s.erase(0, s.find_first_not_of(t));
    }
    return s;
}

string StringUtil::rtrim(const string& str, const char* t)
{
    string s(str);
    if (t) {
        size_t pos = s.find_last_not_of(t);
        if (SIZE_MAX - pos > 1) {
            s.erase(pos + 1);
        }
    }
    return s;
}

StringUtil::StringUtil()
{
}

StringUtil::~StringUtil()
{
}
