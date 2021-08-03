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

#include <fstream>
#include <regex>
#include <string>

#include "util/Logger.h"

#define STR_LEN                 1024

using namespace std;

extern "C" bool getCrashedFunction(const char* crashreport, char* func)
{
    std::ifstream contents(crashreport);
    if (!contents) {
        PLUGIN_ERROR("File open error %s (%d)", crashreport, errno);
        return false;
    }
    string line;
    smatch match;
    while (getline(contents, line)) {
        if (string::npos == line.find("Stack trace of thread"))
            continue;
        getline(contents, line);
        PLUGIN_INFO("Stacktrace : %s", line.c_str());
        // #0  0x0000000000487ba4 _Z5funcCv (coredump_example + 0xba4)
        // #0  0x00000000b6cb3c26 n/a (libc.so.6 + 0x1ac26)
        if (!regex_match(line, match, regex("\\s*#0\\s+0x([0-9a-zA-Z]+)\\s+([[:print:]]+)"))) {
            PLUGIN_DEBUG("Not matched");
        }
        break;
    }
    if (!match.ready() || match.size() != 3) {
        PLUGIN_ERROR("Cannot find stack trace.");
        return false;
    }
    // summary: /usr/bin/coredump_example in _Z5funcCv (coredmp_example + 0xba4)
    snprintf(func, STR_LEN, "in %s", string(match[2]).c_str());
    return true;
}

