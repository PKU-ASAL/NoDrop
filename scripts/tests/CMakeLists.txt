add_executable(helloworld EXCLUDE_FROM_ALL helloworld.c)
add_executable(multithread EXCLUDE_FROM_ALL multithread.c)
target_link_libraries(multithread pthread)

add_custom_target(tests
        DEPENDS multithread helloworld)