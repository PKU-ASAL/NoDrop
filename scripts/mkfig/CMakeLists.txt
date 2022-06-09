set(TARGET draw)
set(DRAW_SOURCES
        draw.cpp
        matplotlibcpp.h
        ${PROJECT_SOURCE_DIR}/include/events.h
        ${PROJECT_SOURCE_DIR}/kmodule/tables/dynamic_params_table.c
        ${PROJECT_SOURCE_DIR}/kmodule/tables/flags_table.c
        ${PROJECT_SOURCE_DIR}/kmodule/tables/events_table.c)
set(COMMON_CFLAGS "-fPIC -std=c++11")
set(COMMON_LDFLAGS "-fpic")

include_directories(${PROJECT_SOURCE_DIR}/include)

include(pyconfig.cmake)

if(NOT PYTHONLIBS_FOUND)
    return()
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${PYTHON_CFLAGS} ${COMMON_CFLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${PYTHON_LDFLAGS} ${COMMON_LDFLAGS}")

add_executable(${TARGET} EXCLUDE_FROM_ALL ${DRAW_SOURCES})
include_directories(${PYTHON_INCLUDE_DIRS})
target_link_libraries(${TARGET} ${PYTHON_LIBRARIES})