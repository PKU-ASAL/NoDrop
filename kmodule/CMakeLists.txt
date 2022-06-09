# Find the kernel release
execute_process(
        COMMAND uname -r
        OUTPUT_VARIABLE KERNEL_RELEASE
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

find_path(
        KERNELHEADERS_DIR
        include/linux/user.h
        PATHS /usr/src/linux-headers-${KERNEL_RELEASE}
)
find_path(
        KERNELHEADERS_ASM
        include/asm/linkage.h
        PATHS /usr/src/linux-headers-${KERNEL_RELEASE}/arch/x86
)

message(STATUS "Kernel release: ${KERNEL_RELEASE}")
message(STATUS "Kernel headers: ${KERNELHEADERS_DIR}")
message(STATUS "Kernel generic: ${KERNELHEADERS_ASM}")

configure_file(Makefile.in src/Makefile)

set(KMODULE_SOURCES
        nod_main.c
        nodrop.h
        loader.c
        trace.c
        proc.c
        procinfo.c
        procinfo.h
        fillers.c
        fillers.h
        events.c
        privil.c
        elf.c
        syscall_table.c
        fillers_table.c
        tables/events_table.c
        tables/flags_table.c
        tables/dynamic_params_table.c
        flags.h
        syscall.h
        ../include/common.h
        ../include/events.h
        ../include/ioctl.h
)

foreach(FILENAME ${KMODULE_SOURCES})
        get_filename_component(TMP_NAME ${FILENAME} NAME)
        configure_file(${FILENAME} src/${TMP_NAME} COPYONLY)
endforeach()

add_definitions(-D__KERNEL__ -DMODULE)

include_directories(
        ${KERNELHEADERS_DIR}/include
        ${KERNELHEADERS_ASM}/include
)
include_directories(${PROJECT_SOURCE_DIR}/include)

add_custom_target(kmodule ALL
        COMMAND ${MAKE_COMMAND}
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different ${PROBE_NAME}.ko "${CMAKE_BINARY_DIR}"
        WORKING_DIRECTORY src
        DEPENDS ${KMODULE_SOURCES}
        VERBATIM)

add_custom_target(load
        COMMAND sudo rmmod ${PROBE_NAME} 2> /dev/null || true
        COMMAND mkdir -p /tmp/${PROBE_NAME}
        COMMAND sudo insmod ${CMAKE_BINARY_DIR}/${PROBE_NAME}.ko
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        DEPENDS kmodule monitor
        VERBATIM)
set_target_properties(load PROPERTIES EXCLUDE_FROM_ALL TRUE)

# This target helps parseing C files for IDEs like CLion
add_library(dummy EXCLUDE_FROM_ALL ${KMODULE_SOURCES})
set_target_properties(dummy PROPERTIES DEPRECATION "DO NOT BUILD THIS TARGET")
