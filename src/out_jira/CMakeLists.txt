set(src
  jira.c)

#set(Python_ADDITIONAL_VERSIONS 2)
find_package(PythonLibs REQUIRED)
#find_package (Python3 COMPONENTS Interpreter Development)
include_directories(${PYTHON_INCLUDE_DIRS})

message("Python_FOUND:${Python_FOUND}")
message("Python_VERSION:${Python_VERSION}")
message("Python_Development_FOUND:${Python_Development_FOUND}")
message("Python_LIBRARIES:${PYTHON_LIBRARIES}")

FLB_PLUGIN(out_jira "${src}" ${PYTHON_LIBRARIES})
#FLB_PLUGIN(out_jira "${src}" "")
