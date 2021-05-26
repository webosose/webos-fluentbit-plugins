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

#ifndef UTIL_LOGGER_H_
#define UTIL_LOGGER_H_

#include "FluentBit.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PLUGIN_NAME_LEN 32

struct LogContext {
    int logLevel;
    char pluginName[PLUGIN_NAME_LEN];
};

struct LogContext* getLogContext();

void setLogContext(int logLevel, char* pluginName);

#define PLUGIN_DEBUG(fmt, ...) \
    if (flb_log_check_level(getLogContext()->logLevel, FLB_LOG_DEBUG)) \
        flb_log_print(FLB_LOG_DEBUG, NULL, 0, "[%s][%s] " fmt, \
                      getLogContext()->pluginName, __FUNCTION__, ##__VA_ARGS__)

#define PLUGIN_INFO(fmt, ...) \
    if (flb_log_check_level(getLogContext()->logLevel, FLB_LOG_INFO)) \
        flb_log_print(FLB_LOG_INFO, NULL, 0, "[%s][%s] " fmt, \
                      getLogContext()->pluginName, __FUNCTION__, ##__VA_ARGS__)

#define PLUGIN_WARN(fmt, ...) \
    if (flb_log_check_level(getLogContext()->logLevel, FLB_LOG_WARN)) \
        flb_log_print(FLB_LOG_WARN, NULL, 0, "[%s][%s] " fmt, \
                      getLogContext()->pluginName, __FUNCTION__, ##__VA_ARGS__)

#define PLUGIN_ERROR(fmt, ...) \
    if (flb_log_check_level(getLogContext()->logLevel, FLB_LOG_ERROR)) \
        flb_log_print(FLB_LOG_ERROR, NULL, 0, "[%s][%s] " fmt, \
                      getLogContext()->pluginName, __FUNCTION__, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* UTIL_LOGGER_H_ */
