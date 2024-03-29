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

#ifndef UTIL_MSGPACKUTIL_H_
#define UTIL_MSGPACKUTIL_H_

#include <msgpack.h>
#include <pbnjson.hpp>
#include <string>

using namespace pbnjson;
using namespace std;

class MSGPackUtil {
public:
    MSGPackUtil() {}
    virtual ~MSGPackUtil() {}

    static bool getValue(const msgpack_object* map, const string& key, msgpack_object** value);
    static bool getValue(const msgpack_object* map, const string& key, string& value);

    static void putValue(msgpack_packer* packer, const string& key, const JValue& value);
    static void putValue(msgpack_packer* packer, const string& key, const string& value);
    static void putValue(msgpack_packer* packer, const string& key, const char* value);
    static void putValue(msgpack_packer* packer, const string& key, int64_t value);
    static void putValue(msgpack_packer* packer, const string& key, double value);
    static void putValue(msgpack_packer* packer, const string& key, bool value);

private:
    static void packStr(msgpack_packer* packer, const string& str);

};

#endif
