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

#ifndef UTIL_JVALUEUTIL_H_
#define UTIL_JVALUEUTIL_H_

#include <iostream>
#include <map>
#include <pbnjson.hpp>

using namespace std;
using namespace pbnjson;

class JValueUtil {
public:
    JValueUtil() {}
    virtual ~JValueUtil() {}

    template <typename T>
    static bool getValue(const JValue& json, const string& key, T& value) {
        if (!json)
            return false;
        if (!json.hasKey(key))
            return false;
        return convertValue(json[key], value);
    }

    template <typename... Args>
    static bool getValue(const JValue& json, const string& key, const string& nextKey, Args& ...rest) {
        if (!json)
            return false;
        if (!json.hasKey(key))
            return false;
        if (!json[key].isObject())
            return false;
        return getValue(json[key], nextKey, rest...);
    }

    template <typename... Args>
    static bool hasKey(const JValue& json, Args ...rest) {
        JValue value;
        return getValue(json, rest..., value);
    }

private:
    static bool convertValue(const JValue& json, JValue& value);
    static bool convertValue(const JValue& json, string& value);
    static bool convertValue(const JValue& json, int& value);
    static bool convertValue(const JValue& json, bool& value);

};

#endif /* UTIL_JVALUEUTIL_H_ */
