# @@@LICENSE
#
#      Copyright (c) 2021-2023 LG Electronics, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# LICENSE@@@

cmake_minimum_required(VERSION 2.8.7)
project(webos-fluentbit-plugins)

include(webOS/webOS)
webos_modules_init(1 6 3)
webos_component(1 0 0)

webos_include_install_paths()

add_subdirectory(plugins)
add_subdirectory(src/coredump_example)
add_subdirectory(python3-webos)
# add_subdirectory(inotify_coredump_test)

# install
file(GLOB fluent-bit_conf files/conf/*.conf)

install(FILES ${fluent-bit_conf} DESTINATION ${WEBOS_INSTALL_SYSCONFDIR}/fluent-bit)

if(${USE_NEW_ACG} MATCHES TRUE)
    message("USE_NEW_ACG is ${USE_NEW_ACG}")
    webos_build_system_bus_files(files/sysbus_new)
else()
    webos_build_system_bus_files(files/sysbus)
endif()

