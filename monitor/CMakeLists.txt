include(CheckCCompilerFlag)
check_c_compiler_flag(--static-pie HAS_STATIC_PIE)
if (NOT HAS_STATIC_PIE)
    message(FATAL_ERROR "Compiler does NOT support --static-pie, try a new version greater than 8.0, current ${CMAKE_C_COMPILER_VERSION}")
endif ()

set(LUA_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../lua")

set(LUA_SOURCES
        ${LUA_SRC_DIR}/lapi.c
        ${LUA_SRC_DIR}/lcode.c
        ${LUA_SRC_DIR}/lctype.c
        ${LUA_SRC_DIR}/ldebug.c
        ${LUA_SRC_DIR}/ldo.c
        ${LUA_SRC_DIR}/ldump.c
        ${LUA_SRC_DIR}/lfunc.c
        ${LUA_SRC_DIR}/lgc.c
        ${LUA_SRC_DIR}/llex.c
        ${LUA_SRC_DIR}/lmem.c
        ${LUA_SRC_DIR}/lobject.c
        ${LUA_SRC_DIR}/lopcodes.c
        ${LUA_SRC_DIR}/lparser.c
        ${LUA_SRC_DIR}/lstate.c
        ${LUA_SRC_DIR}/lstring.c
        ${LUA_SRC_DIR}/ltable.c
        ${LUA_SRC_DIR}/ltm.c
        ${LUA_SRC_DIR}/lundump.c
        ${LUA_SRC_DIR}/lvm.c
        ${LUA_SRC_DIR}/lzio.c
        ${LUA_SRC_DIR}/lauxlib.c
        ${LUA_SRC_DIR}/lbaselib.c
        ${LUA_SRC_DIR}/lcorolib.c
        ${LUA_SRC_DIR}/ldblib.c
        ${LUA_SRC_DIR}/liolib.c
        ${LUA_SRC_DIR}/lmathlib.c
        ${LUA_SRC_DIR}/loslib.c
        ${LUA_SRC_DIR}/lstrlib.c
        ${LUA_SRC_DIR}/ltablib.c
        ${LUA_SRC_DIR}/lutf8lib.c
        ${LUA_SRC_DIR}/linit.c
)


set(MONITOR_SOURCES
        src/main.c
        src/startup.c
        src/lua_runtime.c
        src/lua_runtime.h
        src/dynlink.h
        src/pkeys.h
        mmheap/mmheap.c
        mmheap/mmheap.h
        ../kmodule/tables/dynamic_params_table.c
        ../kmodule/tables/events_table.c
        ../kmodule/tables/flags_table.c
        ../include/tsc.h
        ../include/common.h
        ../include/events.h
        ../include/ioctl.h)
        
list(APPEND MONITOR_SOURCES ${LUA_SOURCES})

foreach (FILENAME ${MONITOR_SOURCES})
    get_filename_component(TMP_NAME ${FILENAME} NAME)
    configure_file(${FILENAME} src/${TMP_NAME} COPYONLY)
endforeach ()

if(PATH_FMT)
        add_definitions(-DPATH_FMT="${PATH_FMT}")
        message(STATUS "Custom path format ${PATH_FMT}")
endif()

configure_file(musl.specs musl.specs COPYONLY)
configure_file(script_x86-64.ld script_x86-64.ld COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/../include/config.h.in 
                ${CMAKE_CURRENT_SOURCE_DIR}/src/config.h)

# here delete -mno-sse due to lua runtime
set(NODROP_COMMON_FLAGS "-Wall -fno-stack-protector -fPIE --static-pie -nostartfiles -specs=musl.specs")
set(NODROP_DEBUG_FLAGS "-ggdb -Og -DDEBUG")
set(NODROP_RELEASE_FLAGS "-Os -DNODEBUG -fno-strict-aliasing")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NODROP_COMMON_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG "${NODROP_DEBUG_FLAGS}")
set(CMAKE_C_FLAGS_RELEASE "${NODROP_RELEASE_FLAGS}")

set(LINKER_SCRIPT "script_x86-64.ld")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -T ${LINKER_SCRIPT}")

include_directories(
        src/
        ../include
        mmheap/
        ${LUA_SRC_DIR}
)

add_executable(${MONITOR} ${MONITOR_SOURCES})
add_custom_command(TARGET ${MONITOR} POST_BUILD
        COMMAND strip -R .symtab ${MONITOR} -o ${MONITOR}
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different monitor "${CMAKE_CURRENT_BINARY_DIR}"
        COMMENT "strip monitor .symtab section"
        VERBATIM)
target_link_libraries(${MONITOR} m)
