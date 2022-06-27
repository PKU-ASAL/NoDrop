# -- Python3 configuration detection script --

# This is a simple replacement for the hopelessly broken
# FindPythonLibs.cmake module and the FindPythonInterp.cmake module.

# Uses a slightly modified `python-config` script
# originally taken from "virtualenv".
# Assumes Python 3.x, does not even attempt to detect Python 2.
# Written by Andras Aszodi.
#
# Takes an input variable PYTHON_MINIMAL_VERSION_REQUIRED
# which should be set to e.g. "3.5". If not set, then 3.0 is assumed.

# Example usage:
# In your top-level CMakeLists.txt, add the following line(s):
#   set(PYTHON_MINIMAL_VERSION_REQUIRED 3.5)  # this is optional
#   include (pyconfig.cmake)
#
# This script returns the following variables:
#
# PYTHON_FOUND               - whether Python3 itself has been found.
# PYTHONLIBS_FOUND           - whether the Python libraries have been found
# PYTHON_INCLUDE_DIRS        - path to where Python.h is found
# PYTHON_LIBRARY_DIRS        - path where the Python libraries are (can be used as -L argument)
# PYTHON_LIBRARIES           - link line, e.g. -lpython3.5m -ldl ...
# PYTHON_CFLAGS              - c flags
# PYTHON_LDFLAGS             - the complete shared library link options

# Init the result variables
set(PYTHONLIBS_FOUND NOTFOUND)
set(PYTHON_INCLUDE_DIRS NOTFOUND)
set(PYTHON_LIBRARY_DIRS NOTFOUND)
set(PYTHON_LIBRARIES NOTFOUND)
set(PYTHON_LDFLAGS NOTFOUND)
set(PYTHON_CFLAGS NOTFOUND)

# The `python-config` script
# NOTE: you may have to edit this location, depending on your setup
if(NOT DEFINED PYTHON_CONFIG)
    set(PYTHON_CONFIG /usr/bin/python3-config)
endif()

# Get the version of the currently active Python interpreter.
# If no Python 3.x or higher is found, then just return.
execute_process(COMMAND ${PYTHON_CONFIG} "--help"
        RESULT_VARIABLE _RETVAL
        OUTPUT_VARIABLE _TMP
        OUTPUT_STRIP_TRAILING_WHITESPACE)
if (NOT(_RETVAL EQUAL 0))
    message(WARNING "Can NOT find python-config")
    return()
endif()

# get include directories
execute_process(COMMAND ${PYTHON_CONFIG} "--includes"
        OUTPUT_VARIABLE _INCLDIRS
        OUTPUT_STRIP_TRAILING_WHITESPACE
        )
# for some reason the include dir is returned twice
# and with -I prepended which must be removed.
separate_arguments(_INCLDIRS_LIST UNIX_COMMAND "${_INCLDIRS}")  # Convert to list
list(GET _INCLDIRS_LIST 0 _IIDIRS)  # save the 1st element
string(REPLACE "-I" "" PYTHON_INCLUDE_DIRS ${_IIDIRS})  # chop off leading -I, save result

# get the config directories
execute_process(COMMAND ${PYTHON_CONFIG} "--configdir"
        OUTPUT_VARIABLE PYTHON_LIBRARY_DIRS
        OUTPUT_STRIP_TRAILING_WHITESPACE
        )

# get the library link line
execute_process(COMMAND ${PYTHON_CONFIG} "--libs"
        OUTPUT_VARIABLE PYTHON_LIBRARIES
        OUTPUT_STRIP_TRAILING_WHITESPACE
        )

# get the library link line
execute_process(COMMAND ${PYTHON_CONFIG} "--cflags"
        OUTPUT_VARIABLE PYTHON_CFLAGS
        OUTPUT_STRIP_TRAILING_WHITESPACE
        )

# complete shared library link options
execute_process(COMMAND ${PYTHON_CONFIG} "--ldflags"
        OUTPUT_VARIABLE PYTHON_LDFLAGS
        OUTPUT_STRIP_TRAILING_WHITESPACE
        )

if (PYTHON_INCLUDE_DIRS AND PYTHON_LIBRARY_DIRS AND PYTHON_LIBRARIES
        AND PYTHON_LDFLAGS AND PYTHON_CFLAGS)
    set(PYTHONLIBS_FOUND FOUND)
endif()