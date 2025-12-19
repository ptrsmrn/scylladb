/*
 * Copyright (C) 2024-present ScyllaDB
 */

/*
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

#pragma once

#include <cstdint>
#include <chrono>
#include <filesystem>
#include <array>
#include <optional>
#include <seastar/core/future.hh>
#include <seastar/core/sharded.hh>
#include <seastar/core/timer.hh>
#include <seastar/core/abort_source.hh>
#include <seastar/core/condition-variable.hh>
#include <seastar/util/optimized_optional.hh>

namespace replica {
class database;
}

namespace service {
class raft_group_registry;
}

namespace license {

// License limits as defined in the ScyllaDB Source Available License 1.0
// https://www.scylladb.com/scylladb-source-available-license/
inline constexpr int64_t default_max_storage_bytes = int64_t(10) * 1024 * 1024 * 1024 * 1024; // 10TB
inline constexpr unsigned default_max_vcpus = 50;

// Unlimited value for licensed customers
inline constexpr int64_t unlimited_storage = -1;
inline constexpr unsigned unlimited_vcpus = 0xFFFFFFFF;

// Default check interval: 1 hour (infrequent to minimize performance impact)
inline constexpr std::chrono::hours default_check_interval{1};

// Grace period: 7 days after license expiry before blocking writes
inline constexpr std::chrono::hours grace_period_duration{24 * 7};  // 7 days

// Default license file name
inline constexpr const char* default_license_filename = "scylla_license.key";

// Ed25519 key sizes
inline constexpr size_t ed25519_seed_size = 32;
inline constexpr size_t ed25519_public_key_size = 32;
inline constexpr size_t ed25519_private_key_size = 64;  // seed + public key
inline constexpr size_t ed25519_signature_size = 64;

// ============================================================================
// License Data Structure
// ============================================================================
// The license contains customer-specific parameters that are signed.
// Format: "SCYLLA_LICENSE:v1:<customer_id>:<expiry_timestamp>:<max_vcpus>:<max_storage_tb>"
// Example: "SCYLLA_LICENSE:v1:ACME_Corp:1735689600:100:50"
//
// - customer_id: Customer identifier string (max 64 chars)
// - expiry_timestamp: Unix timestamp when license expires (0 = never expires)
// - max_vcpus: Maximum allowed vCPUs (0xFFFFFFFF = unlimited)
// - max_storage_tb: Maximum storage in TB (0 = unlimited)

struct license_data {
    seastar::sstring customer_id;
    unsigned max_vcpus = unlimited_vcpus;           // 0xFFFFFFFF = unlimited
    int64_t max_storage_bytes = unlimited_storage;  // -1 = unlimited
    std::chrono::system_clock::time_point expiry;   // epoch = never expires

    bool is_unlimited_vcpus() const { return max_vcpus == unlimited_vcpus; }
    bool is_unlimited_storage() const { return max_storage_bytes == unlimited_storage; }
    bool never_expires() const { return expiry == std::chrono::system_clock::time_point{}; }
    bool is_expired() const {
        if (never_expires()) return false;
        return std::chrono::system_clock::now() > expiry;
    }

    // Serialize to string for signing
    seastar::sstring serialize() const;

    // Parse from string
    static std::optional<license_data> parse(const seastar::sstring& data);
};

struct limits {
    int64_t max_storage_bytes = default_max_storage_bytes;
    unsigned max_vcpus = default_max_vcpus;
};

struct compliance_status {
    int64_t current_storage_bytes = 0;
    unsigned current_vcpus = 0;
    bool storage_limit_exceeded = false;
    bool vcpu_limit_exceeded = false;
    bool has_valid_license = false;
    bool license_expired = false;
    bool in_grace_period = false;           // True if expired but within grace period
    bool grace_period_exceeded = false;      // True if grace period has ended
    std::optional<license_data> license_info;  // Present if has_valid_license

    bool is_compliant() const {
        // Compliant if:
        // 1. Valid, non-expired license, OR
        // 2. Expired but in grace period, OR
        // 3. No license but within default limits
        if (has_valid_license && !license_expired) {
            return true;
        }
        if (license_expired && in_grace_period && !grace_period_exceeded) {
            return true;
        }
        return !storage_limit_exceeded && !vcpu_limit_exceeded;
    }

    bool should_block_writes() const {
        // Block writes only if grace period has ended
        return grace_period_exceeded;
    }
};

// ============================================================================
// Key Generation (for ScyllaDB internal use - generating customer licenses)
// ============================================================================

struct keypair {
    std::array<uint8_t, ed25519_seed_size> seed;           // 32-byte seed
    std::array<uint8_t, ed25519_public_key_size> public_key;  // 32-byte public key
    std::array<uint8_t, ed25519_private_key_size> private_key; // 64-byte private key (seed + pubkey)
};

// Generate a new random Ed25519 keypair.
// This is used by ScyllaDB to generate the master keypair (done once).
// The public key is then embedded in the binary (obfuscated).
keypair generate_keypair();

// Generate a keypair from a specific seed (deterministic).
// Use this to regenerate the same keypair from a stored seed.
keypair generate_keypair_from_seed(const std::array<uint8_t, ed25519_seed_size>& seed);

// ============================================================================
// License Generation (for ScyllaDB internal use)
// ============================================================================

// Generate a signed license file content.
// Parameters:
//   private_key - The 64-byte Ed25519 private key (seed + public key)
//   data - The license parameters for this customer
//
// Returns: The complete license file content (data + signature in hex format)
//
// License file format:
//   Line 1: License data string (e.g., "SCYLLA_LICENSE:v1:ACME:100:50:0")
//   Line 2: Hex-encoded 64-byte signature (128 hex chars)
seastar::sstring generate_license(
    const std::array<uint8_t, ed25519_private_key_size>& private_key,
    const license_data& data);

// ============================================================================
// License Verification (embedded in scylla-server)
// ============================================================================

// Get the embedded public key used for license verification.
// The public key is derived through computation to obscure the literal bytes.
std::array<uint8_t, ed25519_public_key_size> get_license_public_key();

// Parse and verify a license file.
// Returns the license data if valid, nullopt otherwise.
// Checks:
//   1. File format is valid
//   2. Signature is valid (signed with ScyllaDB's private key)
//   3. License is not expired
std::optional<license_data> verify_license_file(const seastar::sstring& content);

// Async version - reads file and verifies
seastar::future<std::optional<license_data>> verify_license_file_async(
    const std::filesystem::path& license_path);

// Check license compliance
compliance_status check_compliance(seastar::sharded<replica::database>& db,
                                   const std::filesystem::path& license_path,
                                   const limits& default_lim = limits{});

seastar::future<compliance_status> check_compliance_async(
    seastar::sharded<replica::database>& db,
    const std::filesystem::path& license_path,
    const limits& default_lim = limits{});

// Calculate total storage used across all shards (for license checks)
seastar::future<int64_t> calculate_total_storage_async(seastar::sharded<replica::database>& db);

// Log compliance warnings
void log_compliance_warning(const compliance_status& status, const limits& lim = limits{});

// ============================================================================
// Compliance Monitor
// ============================================================================

class compliance_monitor {
public:
    using clock_type = seastar::lowres_clock;

    struct config {
        std::chrono::milliseconds check_interval;
        limits default_limits;
        std::filesystem::path license_file_path;

        config()
            : check_interval(std::chrono::duration_cast<std::chrono::milliseconds>(default_check_interval))
            , default_limits()
            , license_file_path(default_license_filename)
        {}

        config(std::chrono::milliseconds interval, limits lim,
               std::filesystem::path license_path = default_license_filename)
            : check_interval(interval)
            , default_limits(lim)
            , license_file_path(std::move(license_path))
        {}
    };

    // Constructor without raft_group_registry - checks on all nodes (legacy/testing)
    compliance_monitor(seastar::abort_source& as,
                       seastar::sharded<replica::database>& db);

    compliance_monitor(seastar::abort_source& as,
                       seastar::sharded<replica::database>& db,
                       config cfg);

    // Constructor with raft_group_registry - checks only on Raft group0 leader
    // This is the preferred constructor for production use to minimize cluster load
    compliance_monitor(seastar::abort_source& as,
                       seastar::sharded<replica::database>& db,
                       seastar::sharded<service::raft_group_registry>& raft_gr,
                       config cfg);

    ~compliance_monitor();

    seastar::future<> start();
    seastar::future<> stop() noexcept;
    void trigger_check() noexcept;

    const compliance_status& last_status() const noexcept { return _last_status; }
    bool is_compliant() const noexcept { return _last_status.is_compliant(); }

    // Get the license data if a valid license is present
    const std::optional<license_data>& license_info() const noexcept {
        return _last_status.license_info;
    }

    // Returns true if this node is responsible for license checks
    // (either Raft leader or Raft not configured)
    bool is_check_node() const noexcept;

private:
    seastar::future<> run_check_loop();
    seastar::future<> do_check();
    bool should_skip_check() const noexcept;

    seastar::optimized_optional<seastar::abort_source::subscription> _as_sub;
    seastar::abort_source _as;
    seastar::condition_variable _check_cv;
    seastar::sharded<replica::database>& _db;
    seastar::sharded<service::raft_group_registry>* _raft_gr = nullptr;  // Optional, for leader-only checks
    config _cfg;
    compliance_status _last_status;
    bool _warning_logged = false;
    seastar::future<> _check_loop_fut = seastar::make_ready_future<>();
};

// ============================================================================
// Utility: Print keypair info for setup
// ============================================================================

// Print the public key in a format suitable for embedding in code.
// Used during initial setup to generate the obfuscated public key constants.
void print_keypair_for_embedding(const keypair& kp);

} // namespace license
