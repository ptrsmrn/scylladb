/*
 * Copyright (C) 2015-present ScyllaDB
 *
 * Modified by ScyllaDB
 */

/*
 * SPDX-License-Identifier: (LicenseRef-ScyllaDB-Source-Available-1.0 and Apache-2.0)
 */

#pragma once

#include <sstream>
#include <antlr4-runtime.h>
#include "bytes.hh"
#include "cql3/error_listener.hh"
#include "exceptions/exceptions.hh"

namespace cql3 {

/**
 * ErrorListener that collects and enhances the errors sent by the CQL lexer and parser.
 *
 * Inherits from antlr4::BaseErrorListener so it can be registered directly with the
 * ANTLR4 lexer/parser, and from cql3::error_listener so grammar action code can call
 * add_recognition_error() to raise errors with a plain string message.
 */
class error_collector
    : public antlr4::BaseErrorListener
    , public cql3::error_listener
{
    /**
     * The CQL query being parsed (used for error context).
     */
    const std::string_view _query;

public:
    explicit error_collector(const std::string_view& query) : _query(query) {}

    // ---- antlr4::BaseErrorListener ----

    /**
     * Called by the ANTLR4 runtime when a syntax error is encountered.
     * Formats line/column info and throws exceptions::syntax_exception.
     */
    [[noreturn]]
    void syntaxError(antlr4::Recognizer* /*recognizer*/,
                     antlr4::Token* /*offendingSymbol*/,
                     size_t line,
                     size_t charPositionInLine,
                     const std::string& msg,
                     std::exception_ptr /*e*/) override
    {
        std::ostringstream result;
        result << "line " << line << ":" << charPositionInLine << " " << msg;
        throw exceptions::syntax_exception(result.str());
    }

    // ---- cql3::error_listener ----

    /**
     * Called from grammar action code via add_recognition_error().
     * Throws exceptions::syntax_exception with the provided message.
     */
    [[noreturn]]
    void syntax_error(const sstring& msg) override {
        throw exceptions::syntax_exception(msg);
    }
};

} // namespace cql3
