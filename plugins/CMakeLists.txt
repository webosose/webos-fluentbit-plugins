# @@@LICENSE
#
#      Copyright (c) 2021 LG Electronics, Inc.
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

include(FindPkgConfig)

pkg_check_modules(GLIB2 REQUIRED glib-2.0)
include_directories(${GLIB2_INCLUDE_DIRS})

pkg_check_modules(PBNJSON_CPP REQUIRED pbnjson_cpp)
include_directories(${PBNJSON_CPP_INCLUDE_DIRS})

webos_configure_header_files(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/common)
include_directories(${CMAKE_BINARY_DIR}/Configured/plugins/common)

file(GLOB_RECURSE COMMON_C ${CMAKE_CURRENT_SOURCE_DIR}/common/*.c)
file(GLOB_RECURSE COMMON_CPP ${CMAKE_CURRENT_SOURCE_DIR}/common/*.cpp)

# Macro to set definitions
macro(FLB_DEFINITION var)
    add_definitions(-D${var})
    set(FLB_BUILD_FLAGS "${FLB_BUILD_FLAGS}#ifndef ${var}\n#define ${var}\n#endif\n")
    set(FLB_INFO_FLAGS "${FLB_INFO_FLAGS} ${var}")
endmacro()

macro(FLB_OPTION option value)
    set(${option} ${value} CACHE INTERNAL "" FORCE)
endmacro()

# Macro to build source code
macro(FLB_PLUGIN name src deps)
    add_library(flb-${name} SHARED ${src} ${COMMON_C} ${COMMON_CPP})
    set_target_properties(flb-${name} PROPERTIES PREFIX "")
    set_target_properties(flb-${name} PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
    target_link_libraries(flb-${name} ${deps} ${GLIB2_LDFLAGS} ${PBNJSON_CPP_LDFLAGS})

    install(TARGETS flb-${name}
        LIBRARY DESTINATION /etc/fluent-bit)
endmacro()

set(WITH_SYSTEM_MALLOC  1 CACHE BOOL "Use system memory allocator")

# Build plugin
FLB_OPTION(FLB_JEMALLOC OFF)

add_subdirectory(in_coredump)
add_subdirectory(out_jira)
add_subdirectory(filter_webos_systemd)
