include(CheckCCompilerFlag)
check_c_compiler_flag(--static-pie HAS_STATIC_PIE)
if (NOT HAS_STATIC_PIE)
    message(FATAL_ERROR "Compiler does NOT support --static-pie, try a new version greater than 8.0, current ${CMAKE_C_COMPILER_VERSION}")
endif ()

set(MONITOR_SOURCES
        src/main.c
        src/startup.c
        src/dynlink.h
        src/pkeys.h
        mmheap/mmheap.c
        mmheap/mmheap.h
        ../kmodule/tables/dynamic_params_table.c
        ../kmodule/tables/events_table.c
        ../kmodule/tables/flags_table.c
        ../include/common.h
        ../include/events.h
        ../include/ioctl.h)

foreach (FILENAME ${MONITOR_SOURCES})
    get_filename_component(TMP_NAME ${FILENAME} NAME)
    configure_file(${FILENAME} src/${TMP_NAME} COPYONLY)
endforeach ()

configure_file(musl.specs musl.specs COPYONLY)
configure_file(script_x86-64.ld script_x86-64.ld COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/../include/config.h.in 
                ${CMAKE_CURRENT_SOURCE_DIR}/src/config.h)

set(NODROP_COMMON_FLAGS "-mno-sse -Wall -ggdb -fPIE -fno-stack-protector --static-pie -specs=musl.specs")
set(NODROP_DEBUG_FLAGS "-Og -DDEBUG")
set(NODROP_RELEASE_FLAGS "-Os -DNODEBUG -fno-strict-aliasing")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${NODROP_COMMON_FLAGS} -nostartfiles")
set(CMAKE_C_FLAGS_DEBUG "${NODROP_DEBUG_FLAGS}")
set(CMAKE_C_FLAGS_RELEASE "${NODROP_RELEASE}")

set(LINKER_SCRIPT "script_x86-64.ld")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -T ${LINKER_SCRIPT}")

include_directories(
        src/
        ../include
        mmheap/
)

add_executable(${MONITOR} ${MONITOR_SOURCES})
add_custom_command(TARGET ${MONITOR} POST_BUILD
        COMMAND strip -R .symtab ${MONITOR} -o ${MONITOR}
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different monitor "${CMAKE_CURRENT_BINARY_DIR}"
        COMMENT "strip monitor .symtab section"
        VERBATIM)