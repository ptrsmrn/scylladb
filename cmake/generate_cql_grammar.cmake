#
# Copyright 2025-present ScyllaDB
#
# SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
#

find_package(ANTLR4 REQUIRED)

# Parse antlr4 grammar files and generate C++ sources.
function(generate_cql_grammar)
  cmake_parse_arguments(parsed_args "" "GRAMMAR;OUTPUT_DIR;SOURCES" "" ${ARGN})
  if(IS_ABSOLUTE ${parsed_args_GRAMMAR})
    set(grammar ${parsed_args_GRAMMAR})
  else()
    set(grammar ${CMAKE_CURRENT_SOURCE_DIR}/${parsed_args_GRAMMAR})
  endif()
  if(parsed_args_OUTPUT_DIR)
    set(gen_dir "${parsed_args_OUTPUT_DIR}")
  else()
    set(gen_dir "${CMAKE_CURRENT_BINARY_DIR}")
  endif()

  get_filename_component(stem "${grammar}" NAME_WE)

  set(outputs "")
  foreach(postfix "Lexer.h" "Lexer.cpp" "Parser.h" "Parser.cpp")
    list(APPEND outputs "${gen_dir}/${stem}${postfix}")
  endforeach()

  add_custom_command(
    DEPENDS ${grammar}
    OUTPUT ${outputs}
    COMMAND ${Java_JAVA_EXECUTABLE} -jar ${ANTLR4_JAR}
            -Dlanguage=Cpp
            -no-listener
            -visitor
            -o "${gen_dir}"
            "${grammar}"
    COMMENT "Generating ANTLR4 sources from ${grammar}"
    VERBATIM)

  set(${parsed_args_SOURCES} ${outputs} PARENT_SCOPE)
endfunction(generate_cql_grammar)
