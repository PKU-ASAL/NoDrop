set(CTRL ctrl)
set(CTRL_SOURCES
        nodrop-ctl.c
        ${PROJECT_SOURCE_DIR}/include/ioctl.h
        ${PROJECT_SOURCE_DIR}/include/common.h
        ${PROJECT_SOURCE_DIR}/include/events.h
        ${PROJECT_SOURCE_DIR}/kmodule/tables/events_table.c
        ${PROJECT_SOURCE_DIR}/kmodule/tables/dynamic_params_table.c
        ${PROJECT_SOURCE_DIR}/kmodule/tables/flags_table.c
        ${PROJECT_SOURCE_DIR}/monitor/src/parser.c
        ${PROJECT_SOURCE_DIR}/monitor/src/parser.h)

include_directories(
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/monitor/src)

add_executable(${CTRL} EXCLUDE_FROM_ALL ${CTRL_SOURCES})

install(PROGRAMS
        ${CMAKE_CURRENT_BINARY_DIR}/${CTRL}
        DESTINATION bin
        RENAME nodrop)