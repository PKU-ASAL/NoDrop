if(EXISTS ${CMAKE_CURRENT_BINARY_DIR}/CMakeLists.txt)
        message(FATAL_ERROR
                "Looks like you are trying to run cmake from the base NoDrop source directory.\n"
                "** RUNNING CMAKE FROM THE BASE NODROP DIRECTORY WILL NOT WORK **\n"
                "To Fix:\n"
                " 1. Remove the CMakeCache.txt file in this directory. ex: rm CMakeCache.txt\n"
                " 2. Create a build directory from here. ex: mkdir build\n"
                " 3. cd into that directory. ex: cd build\n"
                " 4. Run cmake from the build directory. ex: cmake ..\n"
                " 5. Run make from the build directory. ex: make\n"
                "Full paste-able example:\n"
                "( rm -f CMakeCache.txt; mkdir build; cd build; cmake ..; make )\n")
endif()
if(NOT(${CMAKE_HOST_SYSTEM_NAME} MATCHES "Linux"))
        message(FATAL_ERROR
                "NoDrop currently only support Linux Platform.\n"
                "${CMAKE_HOST_SYSTEM_NAME} is NOT supported.\n")
endif()

cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

project("NoDrop")

option(PKEY_SUPPORT "Using Intel Memory Protection Key to protect consumer's memory" ON)

if (NOT DEFINED PROBE_NAME)
        set(PROBE_NAME "nodrop")
endif()

if(${CMAKE_GENERATOR} STREQUAL "Unix Makefiles")
        set(MAKE_COMMAND "$(MAKE)")
else()
        set(MAKE_COMMAND "make")
endif()

if(PKEY_SUPPORT)
        add_definitions(-DNOD_PKEY_SUPPORT)
        message(STATUS "Enable Protection Key")
else()
        message(STATUS "Disable Protection Key")
endif()

if(NOT BUFFER_SIZE)
        set(BUFFER_SIZE 8*Mib)
endif()

if(NOT MONITOR)
        set(MONITOR monitor)
endif()

if(NOT MONITOR_PATH)
        set(MONITOR_PATH ${PROJECT_BINARY_DIR}/monitor/${MONITOR})
endif()

if(NOT STORE_PATH)
        set(STORE_PATH /tmp/nodrop)
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

message(STATUS "Buffer size: ${BUFFER_SIZE}")
message(STATUS "Monitor path: ${MONITOR_PATH}")
message(STATUS "Store path: ${STORE_PATH}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

add_subdirectory(kmodule ${PROJECT_BINARY_DIR}/kmodule)
add_subdirectory(monitor ${PROJECT_BINARY_DIR}/monitor)
add_subdirectory(scripts ${PROJECT_BINARY_DIR}/scripts)
