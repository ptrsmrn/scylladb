/*
 * Copyright (C) 2024-present ScyllaDB
 */

/*
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

#include "api/license.hh"

#include <seastar/http/handlers.hh>
#include <seastar/json/json_elements.hh>

#include "api/api.hh"
#include "api/api-doc/license.json.hh"
#include "service/license_service.hh"

namespace api {

using namespace seastar;
using namespace seastar::httpd;

static future<json::json_return_type>
rest_get_license_status(http_context& ctx, sharded<service::license_service>& ls, std::unique_ptr<http::request> req) {
    auto status = co_await ls.local().get_status();

    license_json::license_status result;
    result.status = service::license_service::status_to_string(status.status);
    if (status.customer_id) {
        result.customer_id = *status.customer_id;
    }
    if (status.message) {
        result.message = *status.message;
    }

    co_return result;
}

static future<json::json_return_type>
rest_upload_license(http_context& ctx, sharded<service::license_service>& ls, std::unique_ptr<http::request> req) {
    // Read body content from the request stream
    auto buf = co_await util::read_entire_stream_contiguous(*req->content_stream);
    sstring content(buf.begin(), buf.end());

    try {
        co_await ls.local().upload_license(content);
        co_return json::json_void();
    } catch (const std::invalid_argument& e) {
        throw bad_request_exception(e.what());
    }
}

static future<json::json_return_type>
rest_get_license_usage(http_context& ctx, sharded<service::license_service>& ls, std::unique_ptr<http::request> req) {
    auto usage = co_await ls.local().get_usage();

    license_json::license_usage result;
    if (usage.customer_id) {
        result.customer_id = *usage.customer_id;
    }
    if (usage.expiry_timestamp) {
        result.expiry_timestamp = *usage.expiry_timestamp;
    }
    if (usage.max_vcpus) {
        result.max_vcpus = *usage.max_vcpus;
    }
    if (usage.max_storage_bytes) {
        result.max_storage_bytes = *usage.max_storage_bytes;
    }
    result.current_vcpus = usage.current_vcpus;
    result.current_storage_bytes = usage.current_storage_bytes;
    result.vcpu_limit_exceeded = usage.vcpu_limit_exceeded;
    result.storage_limit_exceeded = usage.storage_limit_exceeded;

    co_return result;
}

static future<json::json_return_type>
rest_delete_license(http_context& ctx, sharded<service::license_service>& ls, std::unique_ptr<http::request> req) {
    co_await ls.local().delete_license();
    co_return json::json_void();
}

void set_license(http_context& ctx, routes& r, sharded<service::license_service>& ls) {
    license_json::get_license_status.set(r, [&ctx, &ls] (std::unique_ptr<http::request> req) {
        return rest_get_license_status(ctx, ls, std::move(req));
    });

    license_json::upload_license.set(r, [&ctx, &ls] (std::unique_ptr<http::request> req) {
        return rest_upload_license(ctx, ls, std::move(req));
    });

    license_json::get_license_usage.set(r, [&ctx, &ls] (std::unique_ptr<http::request> req) {
        return rest_get_license_usage(ctx, ls, std::move(req));
    });

    license_json::delete_license.set(r, [&ctx, &ls] (std::unique_ptr<http::request> req) {
        return rest_delete_license(ctx, ls, std::move(req));
    });
}

void unset_license(http_context& ctx, routes& r) {
    license_json::get_license_status.unset(r);
    license_json::upload_license.unset(r);
    license_json::get_license_usage.unset(r);
    license_json::delete_license.unset(r);
}

} // namespace api

