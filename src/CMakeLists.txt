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
  add_library(flb-${name} SHARED ${src})
  set_target_properties(flb-${name} PROPERTIES PREFIX "")
  set_target_properties(flb-${name} PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
  target_link_libraries(flb-${name} ${deps})

  install(TARGETS flb-${name} 
          LIBRARY DESTINATION /etc/fluent-bit)
endmacro()

set(WITH_SYSTEM_MALLOC  1 CACHE BOOL "Use system memory allocator")


# Build plugin

FLB_OPTION(FLB_JEMALLOC OFF)

set (PLUGIN_NAME  "in_coredump")
add_subdirectory(${PLUGIN_NAME})

set (PLUGIN_NAME  "out_jira")
add_subdirectory(${PLUGIN_NAME})


