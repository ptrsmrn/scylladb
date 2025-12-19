/*
 * Copyright (C) 2024-present ScyllaDB
 */

/*
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

#pragma once

#include <seastar/core/abort_source.hh>
#include <seastar/core/sharded.hh>
#include <seastar/core/sstring.hh>

#include "license_compliance.hh"
#include "service/raft/raft_group0_client.hh"

namespace cql3 {
class query_processor;
}

namespace replica {
class database;
}

namespace service {

class raft_group_registry;

// License service manages license storage and validation via Raft-replicated system.licenses table.
// This provides:
// - Tamper resistance: users can't directly modify license data via CQL
// - Cluster-wide consistency: license automatically propagates to all nodes via Raft
// - REST API: clean interface for license upload and status queries
class license_service : public seastar::peering_sharded_service<license_service> {
public:
    // License status for API responses
    enum class license_status {
        no_license,     // No license uploaded
        valid,          // License is valid and not expired
        expired,        // License signature valid but expired
        invalid,        // License signature invalid or tampered
    };

    static sstring status_to_string(license_status s) {
        switch (s) {
            case license_status::no_license: return "no_license";
            case license_status::valid: return "valid";
            case license_status::expired: return "expired";
            case license_status::invalid: return "invalid";
        }
        return "unknown";
    }

    // Stored license entry in system.licenses
    struct license_entry {
        seastar::sstring license_data;              // Raw license string
        seastar::sstring signature;                 // Hex-encoded signature
        db_clock::time_point uploaded_at;           // When uploaded
        seastar::sstring customer_id;               // Extracted customer ID
        int64_t expiry_timestamp;                   // Extracted expiry (0 = never)
        int64_t grace_period_start_timestamp = 0;   // When grace period started (0 = not started)
        seastar::sstring grace_period_signature;    // Signature of license_data + grace_start
    };

    // License status response for GET /license/status
    struct status_response {
        license_status status;
        std::optional<seastar::sstring> customer_id;
        std::optional<seastar::sstring> message;
        std::optional<int64_t> grace_period_ends_at;    // Unix timestamp when grace period ends
        std::optional<int64_t> days_until_write_block;  // Days remaining in grace period
    };

    // License usage response for GET /license/usage
    struct usage_response {
        std::optional<seastar::sstring> customer_id;
        std::optional<int64_t> expiry_timestamp;        // Unix timestamp, 0 = never
        std::optional<unsigned> max_vcpus;              // License limit (nullopt = unlimited)
        std::optional<int64_t> max_storage_bytes;       // License limit (nullopt = unlimited)
        unsigned current_vcpus;                          // Current usage
        int64_t current_storage_bytes;                   // Current usage
        bool vcpu_limit_exceeded;
        bool storage_limit_exceeded;
    };

    license_service(
        seastar::abort_source& abort_source,
        service::raft_group0_client& group0_client,
        cql3::query_processor& qp,
        seastar::sharded<replica::database>& db
    );

    // Upload a new license (POST /license/upload)
    // Content format: license_data line + signature line (same as file format)
    seastar::future<> upload_license(const seastar::sstring& license_content);

    // Get license status (GET /license/status)
    seastar::future<status_response> get_status();

    // Get license usage info (GET /license/usage)
    seastar::future<usage_response> get_usage();

    // Get current license if any
    seastar::future<std::optional<license_entry>> get_license();

    // Delete current license (for testing/admin)
    seastar::future<> delete_license();

    // Verify and parse a license (used by compliance monitor)
    std::optional<license::license_data> verify_license(const license_entry& entry);

    // Check if license is expired and start grace period if needed
    // This is called periodically by the compliance monitor
    seastar::future<> check_and_update_grace_period();

    // Check if writes should be blocked due to expired grace period
    // Returns true if grace period has ended, false otherwise
    seastar::future<bool> is_write_blocked();

    // Check if DELETE operations are allowed
    // Returns true - deletes are ALWAYS allowed, even after grace period
    // This allows users to reduce their storage/data to get back into compliance
    seastar::future<bool> is_delete_allowed() {
        // Deletes are always allowed to enable recovery
        co_return true;
    }

private:
    seastar::future<> upload_license_inner(const license_entry& entry);
    seastar::future<> delete_license_inner();
    seastar::future<> start_grace_period_inner(int64_t grace_start_timestamp);

    // Generate signature for grace period data
    // Signs: license_data + ":" + grace_period_start_timestamp
    seastar::sstring generate_grace_period_signature(
        const seastar::sstring& license_data,
        int64_t grace_period_start_timestamp);

    // Verify grace period signature
    bool verify_grace_period_signature(
        const seastar::sstring& license_data,
        int64_t grace_period_start_timestamp,
        const seastar::sstring& signature);

    template <typename Func>
    seastar::future<> with_retry(Func&& func);

    static constexpr const char* LICENSE_KEY = "current";

    seastar::abort_source& _abort_source;
    service::raft_group0_client& _group0_client;
    cql3::query_processor& _qp;
    seastar::sharded<replica::database>& _db;
};

} // namespace service

