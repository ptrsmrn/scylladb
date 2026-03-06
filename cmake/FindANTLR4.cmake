#
# Copyright 2025-present ScyllaDB
#

#
# SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
#

# Find ANTLR4 C++ runtime headers and library.
# Searches standard system paths plus /opt/scylladb.

find_path(ANTLR4_INCLUDE_DIR
  NAMES antlr4-runtime.h
  PATHS
    /opt/scylladb/include
    /usr/include/antlr4-runtime
    /usr/local/include/antlr4-runtime)

find_library(ANTLR4_LIBRARY
  NAMES antlr4-runtime
  PATHS
    /opt/scylladb/lib
    /opt/scylladb/lib64
    /usr/lib
    /usr/lib64
    /usr/local/lib
    /usr/local/lib64)

# Find the ANTLR4 tool JAR.  Check vendored location first (tools/antlr4.jar),
# then common system locations.
find_file(ANTLR4_JAR
  NAMES antlr4.jar antlr-4-complete.jar antlr-4.13.2-complete.jar
  PATHS
    ${CMAKE_SOURCE_DIR}/tools
    /opt/scylladb/share/java
    /usr/share/java
    /usr/local/share/java)

find_program(Java_JAVA_EXECUTABLE
  NAMES java
  PATHS
    /usr/bin
    /usr/local/bin)

mark_as_advanced(
  ANTLR4_INCLUDE_DIR
  ANTLR4_LIBRARY
  ANTLR4_JAR
  Java_JAVA_EXECUTABLE)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(ANTLR4
  REQUIRED_VARS
    ANTLR4_INCLUDE_DIR
    ANTLR4_LIBRARY
    ANTLR4_JAR
    Java_JAVA_EXECUTABLE)

if(ANTLR4_FOUND)
  set(ANTLR4_INCLUDE_DIRS ${ANTLR4_INCLUDE_DIR})
  set(ANTLR4_LIBRARIES ${ANTLR4_LIBRARY})

  if(NOT TARGET ANTLR4::antlr4-runtime)
    add_library(ANTLR4::antlr4-runtime UNKNOWN IMPORTED)
    set_target_properties(ANTLR4::antlr4-runtime
      PROPERTIES
        IMPORTED_LOCATION ${ANTLR4_LIBRARY}
        INTERFACE_INCLUDE_DIRECTORIES ${ANTLR4_INCLUDE_DIR})
  endif()
endif()

