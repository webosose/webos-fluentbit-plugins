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

pkg_check_modules(GLIB2 REQUIRED glib-2.0)
include_directories(${GLIB2_INCLUDE_DIRS})

pkg_check_modules(PBNJSON_CPP REQUIRED pbnjson_cpp)
include_directories(${PBNJSON_CPP_INCLUDE_DIRS})

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../common)

file(GLOB_RECURSE COMMON_C ${CMAKE_CURRENT_SOURCE_DIR}/../common/*.c)
file(GLOB_RECURSE COMMON_CPP ${CMAKE_CURRENT_SOURCE_DIR}/../common/*.cpp)
file(GLOB_RECURSE SRC_C ${CMAKE_CURRENT_SOURCE_DIR}/*.c)
file(GLOB_RECURSE SRC_CPP ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)

set(SRC
  ${COMMON_C}
  ${COMMON_CPP}
  ${SRC_C}
  ${SRC_CPP}
)

FLB_PLUGIN(filter_webos_systemd "${SRC}" "-lglib-2.0 -lpbnjson_cpp")
