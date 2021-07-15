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

#include "util/JValueUtil.h"

bool JValueUtil::convertValue(const JValue& json, JValue& value)
{
    value = json;
    return true;
}

bool JValueUtil::convertValue(const JValue& json, string& value)
{
    if (!json.isString())
        return false;
    if (json.asString(value) != CONV_OK) {
        value = "";
        return false;
    }
    return true;
}

bool JValueUtil::convertValue(const JValue& json, int& value)
{
    if (!json.isNumber())
        return false;
    if (json.asNumber<int>(value) != CONV_OK) {
        value = 0;
        return false;
    }
    return true;
}

bool JValueUtil::convertValue(const JValue& json, bool& value)
{
    if (!json.isBoolean())
        return false;
    if (json.asBool(value) != CONV_OK) {
        value = false;
        return false;
    }
    return true;
}
