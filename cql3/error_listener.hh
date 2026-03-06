/*
 * Copyright (C) 2015-present ScyllaDB
 *
 * Modified by ScyllaDB
 */

/*
 * SPDX-License-Identifier: (LicenseRef-ScyllaDB-Source-Available-1.0 and Apache-2.0)
 */

#pragma once

#include <string>
#include <seastar/core/sstring.hh>

namespace cql3 {

/**
 * Listener used to collect the syntax errors emitted by the CQL lexer and parser.
 *
 * This is a simple non-templated interface used by both the lexer and parser members
 * injected via the ANTLR4 grammar @lexer::members / @parser::members sections.
 */
class error_listener {
public:
    virtual ~error_listener() = default;

    /**
     * Invoked when a syntax error with a specified message occurs.
     *
     * @param error_msg the error message (already formatted with line/column info)
     */
    virtual void syntax_error(const sstring& error_msg) = 0;
};

}
