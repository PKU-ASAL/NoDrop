set(CTRL ctrl)
set(CTRL_SOURCES
        nodrop-ctl.c
        ${PROJECT_SOURCE_DIR}/include/ioctl.h)
include_directories(${PROJECT_SOURCE_DIR}/include)

add_executable(${CTRL} EXCLUDE_FROM_ALL ${CTRL_SOURCES})