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

#ifndef UTIL_ERRCODE_H_
#define UTIL_ERRCODE_H_

enum ErrCode {
    ErrCode_NONE = 0,
    ErrCode_INTERNAL_ERROR = 1,
    ErrCode_INVALID_REQUEST_PARAMS = 2,
    ErrCode_LOGIN_FAILURE = 3,
};

extern const char* strerror(enum ErrCode errCode);

#endif
