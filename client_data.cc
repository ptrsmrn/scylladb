/*
 * Copyright (C) 2019-present ScyllaDB
 */

/*
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

#include "client_data.hh"

#include <ranges>
#include <cctype>
#include <magic_enum/magic_enum.hpp>

sstring to_string(client_type ct) {
    return sstring(magic_enum::enum_name(ct));
}

sstring to_string(client_connection_stage ccs) {
    return std::views::all(magic_enum::enum_name(ccs))
         | std::views::transform([](unsigned char c) { return std::toupper(c); })
         | std::ranges::to<sstring>();
}
