configure_file(1.txt 1.txt COPYONLY)
configure_file(attack.sh attack.sh COPYONLY)

add_executable(stress EXCLUDE_FROM_ALL stress.c)
add_executable(attack EXCLUDE_FROM_ALL attack.c)
