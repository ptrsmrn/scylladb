/*
 * Copyright (C) 2015-present ScyllaDB
 */

/*
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

#pragma once

#include <string>
#include "build_mode.hh"

std::string scylla_version();

std::string scylla_build_mode();

// Returns the product name (e.g., "scylla" or "scylla-enterprise")
std::string scylla_product();

// Returns true if this is an enterprise build
bool is_enterprise_build();

// Generate the documentation link, which is appropriate for the current version
// and product (open-source or enterprise).
//
// Will return a documentation URL like this:
//      https://${product}.docs.scylladb.com/${branch}/${url_tail}
//
std::string doc_link(std::string_view url_tail);
