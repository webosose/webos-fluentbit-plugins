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

#include "ErrCode.h"

const char* ErrCodeToStr(enum ErrCode errCode)
{
    switch (errCode) {
    case ErrCode_NONE:
        return "Success";
    case ErrCode_INTERNAL_ERROR:
        return "Internal error";
    case ErrCode_DEPRECATED_METHOD:
        return "Deprecated method";
    case ErrCode_INVALID_REQUEST_PARAMS:
        return "Invalid request params";
    case ErrCode_LOGIN_FAILED:
        return "Login failed";
    case ErrCode_FORK_FAILED:
        return "Fork failed";
    }
    return "Undefined error";
}
