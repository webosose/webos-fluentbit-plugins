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

#ifndef UTIL_STRINGUTIL_H_
#define UTIL_STRINGUTIL_H_

#include <string>

using namespace std;

class StringUtil {
public:
    static string trim(const string& str, const char* t = " \t\n\r\f\v");
    static string ltrim(const string& str, const char* t = " \t\n\r\f\v");
    static string rtrim(const string& str, const char* t = " \t\n\r\f\v");

    StringUtil();
    virtual ~StringUtil();
};

#endif /* UTIL_FILE_H_ */
