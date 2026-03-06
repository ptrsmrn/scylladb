/*
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

/* Copyright 2020-present ScyllaDB */

#include "utils/assert.hh"
#include "util.hh"
#include "cql3/expr/expr-utils.hh"
#include "db/config.hh"
#include <antlr4-runtime.h>
#include "cql3/CqlLexer.h"
#include "cql3/CqlParser.h"

namespace cql3::util {

void do_with_parser_impl(const std::string_view& cql, dialect d, noncopyable_function<void(cql3_parser::CqlParser& parser)> f) {
    cql3::error_collector ec(cql);

    antlr4::ANTLRInputStream input(cql.data(), cql.size());

    cql3_parser::CqlLexer lexer(&input);
    lexer.removeErrorListeners();
    lexer.addErrorListener(&ec);
    // Wire the grammar-injected set_error_listener so action code can call add_recognition_error()
    lexer.set_error_listener(ec);

    antlr4::CommonTokenStream tokens(&lexer);

    cql3_parser::CqlParser parser(&tokens);
    parser.removeErrorListeners();
    parser.addErrorListener(&ec);
    parser.set_error_listener(ec);
    parser.set_dialect(d);
    // Disable parse tree construction: the grammar uses embedded actions to build the ScyllaDB
    // AST directly during the parse, so the ANTLR4 CST is never used. Disabling it saves
    // memory for large queries without affecting correctness.
    parser.setBuildParseTree(false);

    // Use full LL prediction mode to correctly handle all CQL constructs, including
    // keywords-as-identifiers which require LL's full lookahead.
    parser.getInterpreter<antlr4::atn::ParserATNSimulator>()->setPredictionMode(antlr4::atn::PredictionMode::LL);

    f(parser);
}

void validate_timestamp(const db::config& config, const query_options& options, const std::unique_ptr<attributes>& attrs) {
    if (attrs->is_timestamp_set() && config.restrict_future_timestamp()) {
        static constexpr int64_t MAX_DIFFERENCE = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::days(3)).count();
        auto now = std::chrono::duration_cast<std::chrono::microseconds>(db_clock::now().time_since_epoch()).count();

        auto timestamp = attrs->get_timestamp(now, options);

        if (timestamp > now && timestamp - now > MAX_DIFFERENCE) {
            throw exceptions::invalid_request_exception("Cannot provide a timestamp more than 3 days into the future. If this was not intended, "
            "make sure the timestamp is in microseconds. You can also disable this check by setting the restrict_future_timestamp "
            "configuration option to false.");
        }
    }
}

sstring relations_to_where_clause(const expr::expression& e) {
    auto expr_to_pretty_string = [](const expr::expression& e) -> sstring {
        return fmt::format("{:user}", e);
    };
    auto relations = expr::boolean_factors(e);
    auto expressions = relations | std::views::transform(expr_to_pretty_string);
    return fmt::to_string(fmt::join(expressions, " AND "));
}

expr::expression where_clause_to_relations(const std::string_view& where_clause, dialect d) {
    return do_with_parser(where_clause, d, std::mem_fn(&cql3_parser::CqlParser::whereClause_expr));
}

sstring rename_columns_in_where_clause(const std::string_view& where_clause, std::vector<std::pair<::shared_ptr<column_identifier>, ::shared_ptr<column_identifier>>> renames, dialect d) {
    std::vector<expr::expression> relations = boolean_factors(where_clause_to_relations(where_clause, d));
    std::vector<expr::expression> new_relations;
    new_relations.reserve(relations.size());

    for (const expr::expression& old_relation : relations) {
        new_relations.emplace_back(
            expr::search_and_replace(old_relation,
                [&](const expr::expression& e) -> std::optional<expr::expression> {
                    for (const auto& [view_from, view_to] : renames) {
                        if (auto ident = expr::as_if<expr::unresolved_identifier>(&e)) {
                            auto from = column_identifier::raw(view_from->text(), true);
                            if (*ident->ident == from) {
                                return expr::unresolved_identifier{
                                    ::make_shared<column_identifier::raw>(view_to->text(), true)
                                };
                            }
                        }
                    }
                    return std::nullopt;
                }
            )
        );
    }

    return relations_to_where_clause(expr::conjunction{std::move(new_relations)});
}

}
