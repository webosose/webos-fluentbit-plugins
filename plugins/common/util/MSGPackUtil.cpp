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

#include "util/MSGPackUtil.h"

bool MSGPackUtil::getValue(const msgpack_object* map, const string& key, msgpack_object** value)
{
    if (map == NULL || map->type != MSGPACK_OBJECT_MAP) {
        return false;
    }
    const char *pKey;
    uint32_t keyLen;
    for (uint32_t idx = 0; idx < map->via.map.size; idx++) {
        if (MSGPACK_OBJECT_STR != map->via.map.ptr[idx].key.type) {
            continue;
        }
        pKey = map->via.map.ptr[idx].key.via.str.ptr;
        keyLen = map->via.map.ptr[idx].key.via.str.size;
        if (key.length() == keyLen && strncmp(pKey, key.c_str(), keyLen) == 0) {
            *value = &map->via.map.ptr[idx].val;
            return true;
        }
    }
    return false;
}

bool MSGPackUtil::getValue(const msgpack_object* map, const string& key, string& value)
{
    msgpack_object* obj;
    if (!getValue(map, key, &obj) || obj == NULL) {
        return false;
    }
    if (MSGPACK_OBJECT_STR != obj->type) {
        return false;
    }
    value = string(obj->via.str.ptr, obj->via.str.size);
    return true;
}

void MSGPackUtil::putValue(msgpack_packer* packer, const string& key, const JValue& value)
{
    if (!value.isObject()) {
        return;
    }
    if (!key.empty()) {
        packStr(packer, key);
    }
    msgpack_pack_map(packer, (size_t)value.objectSize());

    string numberStr;
    for (auto& kv : value.children()) {
        switch (kv.second.getType()) {
        case JV_BOOL:
            putValue(packer, kv.first.asString(), kv.second.asBool());
            break;
        case JV_NUM:
            // pbnjson does not distinguish integer from floating point (even if the serialized form is X.000000). This is by design.
            putValue(packer, kv.first.asString(), kv.second.asNumber<int>());
            break;
        case JV_STR:
            putValue(packer, kv.first.asString(), kv.second.asString());
            break;
        case JV_OBJECT:
            putValue(packer, kv.first.asString(), kv.second);
            break;
        case JV_ARRAY:
            packStr(packer, kv.first.asString());
            msgpack_pack_array(packer, kv.second.arraySize());
            for (uint32_t i = 0; i < kv.second.arraySize(); ++i) {
                // TODO Support other type's array. Now support only string array.
                if (kv.second[i].getType() != JV_STR) {
                    packStr(packer, "Not implemented");
                    continue;
                }
                packStr(packer, kv.second[i].asString());
            }
            break;
        case JV_NULL:
        default:
            putValue(packer, kv.first.asString(), "Not implemented");
        }
    }
}

void MSGPackUtil::putValue(msgpack_packer* packer, const string& key, const string& value)
{
    packStr(packer, key);
    packStr(packer, value);
}

void MSGPackUtil::putValue(msgpack_packer* packer, const string& key, const char* value)
{
    putValue(packer, key, string(value));
}

void MSGPackUtil::putValue(msgpack_packer* packer, const string& key, int value)
{
    packStr(packer, key);
    msgpack_pack_int(packer, value);
}

void MSGPackUtil::putValue(msgpack_packer* packer, const string& key, double value)
{
    packStr(packer, key);
    msgpack_pack_double(packer, value);
}

void MSGPackUtil::putValue(msgpack_packer* packer, const string& key, bool value)
{
    packStr(packer, key);
    (value) ? msgpack_pack_true(packer) : msgpack_pack_false(packer);
}

void MSGPackUtil::packStr(msgpack_packer* packer, const string& str)
{
    msgpack_pack_str(packer, str.length());
    msgpack_pack_str_body(packer, str.c_str(), str.length());
}
