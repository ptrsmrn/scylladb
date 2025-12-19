/*
 * Copyright (C) 2024-present ScyllaDB
 */

/*
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

#pragma once

#include <seastar/core/sharded.hh>

namespace seastar::httpd { class routes; }

namespace service {
class license_service;
}

namespace api {

struct http_context;

void set_license(http_context& ctx, seastar::httpd::routes& r, seastar::sharded<service::license_service>& ls);
void unset_license(http_context& ctx, seastar::httpd::routes& r);

} // namespace api

