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

void MSGPackUtil::packStr(msgpack_packer* packer, const string& str)
{
    msgpack_pack_str(packer, str.length());
    msgpack_pack_str_body(packer, str.c_str(), str.length());
}

void MSGPackUtil::packMap(msgpack_packer* packer, const string& key, size_t n)
{
    packStr(packer, key);
    msgpack_pack_map(packer, n);
}

void MSGPackUtil::packKeyVal(msgpack_packer* packer, const string& key, const string& val)
{
    packStr(packer, key);
    packStr(packer, val);
}

void MSGPackUtil::packKeyVal(msgpack_packer* packer, const string& key, const int& val)
{
    packStr(packer, key);
    msgpack_pack_int(packer, val);
}

void MSGPackUtil::packKeyVal(msgpack_packer* packer, const string& key, const double& val)
{
    packStr(packer, key);
    msgpack_pack_double(packer, val);
}
