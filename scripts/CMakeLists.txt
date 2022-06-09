add_subdirectory(ctrl)
add_subdirectory(mkfig)
add_subdirectory(StressTesting)
add_subdirectory(tests)
add_custom_target(scripts
        DEPENDS ctrl mkfig attack stress tests)