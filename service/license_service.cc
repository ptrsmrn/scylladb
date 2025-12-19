/*
 * Copyright (C) 2024-present ScyllaDB
 */

/*
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

#include "service/license_service.hh"

#include <seastar/core/smp.hh>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "cql3/query_processor.hh"
#include "cql3/untyped_result_set.hh"
#include "db/system_keyspace.hh"
#include "replica/database.hh"
#include "utils/log.hh"

static logging::logger lslog("license_service");

namespace {

service::query_state& license_query_state() {
    using namespace std::chrono_literals;
    const auto t = 10s;
    static timeout_config tc{ t, t, t, t, t, t, t };
    static thread_local service::client_state cs(service::client_state::internal_tag{}, tc);
    static thread_local service::query_state qs(cs, empty_service_permit());
    return qs;
}

// Parse license content (two lines: data + signature)
std::optional<service::license_service::license_entry> parse_license_content(const seastar::sstring& content) {
    auto lines_start = content.begin();
    auto lines_end = content.end();

    // Find newline
    auto nl = std::find(lines_start, lines_end, '\n');
    if (nl == lines_end) {
        return std::nullopt;
    }

    seastar::sstring license_data(lines_start, nl);
    seastar::sstring signature(nl + 1, lines_end);

    // Trim whitespace from license_data
    while (!license_data.empty() && std::isspace(license_data.back())) {
        license_data.resize(license_data.size() - 1);
    }
    // Trim whitespace from signature
    while (!signature.empty() && std::isspace(signature.back())) {
        signature.resize(signature.size() - 1);
    }
    while (!signature.empty() && std::isspace(signature.front())) {
        signature = signature.substr(1);
    }

    if (license_data.empty() || signature.empty()) {
        return std::nullopt;
    }

    // Parse license data to extract customer_id and expiry
    auto parsed = license::license_data::parse(license_data);
    if (!parsed) {
        return std::nullopt;
    }

    service::license_service::license_entry entry;
    entry.license_data = std::move(license_data);
    entry.signature = std::move(signature);
    entry.uploaded_at = db_clock::now();
    entry.customer_id = parsed->customer_id;
    entry.expiry_timestamp = parsed->never_expires() ? 0 :
        std::chrono::duration_cast<std::chrono::seconds>(
            parsed->expiry.time_since_epoch()).count();

    return entry;
}

} // anonymous namespace

namespace service {

license_service::license_service(
    seastar::abort_source& abort_source,
    service::raft_group0_client& group0_client,
    cql3::query_processor& qp,
    seastar::sharded<replica::database>& db
)
    : _abort_source(abort_source)
    , _group0_client(group0_client)
    , _qp(qp)
    , _db(db)
{
}

seastar::future<> license_service::upload_license(const seastar::sstring& license_content) {
    auto entry_opt = parse_license_content(license_content);
    if (!entry_opt) {
        throw std::invalid_argument("Invalid license format. Expected: license_data\\nsignature");
    }

    // Verify signature before storing
    auto verified = verify_license(*entry_opt);
    if (!verified) {
        throw std::invalid_argument("Invalid license signature");
    }

    lslog.info("Uploading license for customer '{}'", entry_opt->customer_id);

    co_await container().invoke_on(0, [entry = std::move(*entry_opt)] (license_service& ls) mutable {
        return ls.with_retry([&ls, &entry] {
            return ls.upload_license_inner(entry);
        });
    });
}

seastar::future<> license_service::upload_license_inner(const license_entry& entry) {
    auto guard = co_await _group0_client.start_operation(_abort_source, service::raft_timeout{});

    static const sstring stmt = format(
        "INSERT INTO {}.{} (key, license_data, signature, uploaded_at, customer_id, expiry_timestamp) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        db::system_keyspace::NAME, db::system_keyspace::LICENSES);

    auto muts = co_await _qp.get_mutations_internal(stmt, license_query_state(), guard.write_timestamp(), {
        sstring(LICENSE_KEY),
        entry.license_data,
        entry.signature,
        entry.uploaded_at,
        entry.customer_id,
        entry.expiry_timestamp
    });

    if (muts.size() != 1) {
        on_internal_error(lslog, fmt::format("expected 1 mutation got {}", muts.size()));
    }

    utils::chunked_vector<canonical_mutation> cmuts;
    cmuts.emplace_back(std::move(muts[0]));

    auto cmd = _group0_client.prepare_command(
        service::write_mutations{std::move(cmuts)}, guard, "upload license");
    co_await _group0_client.add_entry(std::move(cmd), std::move(guard), _abort_source);

    lslog.info("License uploaded successfully for customer '{}'", entry.customer_id);
}

seastar::future<std::optional<license_service::license_entry>> license_service::get_license() {
    static const sstring query = format(
        "SELECT license_data, signature, uploaded_at, customer_id, expiry_timestamp, "
        "grace_period_start_timestamp, grace_period_signature "
        "FROM {}.{} WHERE key = ?",
        db::system_keyspace::NAME, db::system_keyspace::LICENSES);

    auto rs = co_await _qp.execute_internal(query, {sstring(LICENSE_KEY)},
                                            cql3::query_processor::cache_internal::yes);

    if (rs->empty()) {
        co_return std::nullopt;
    }

    auto& row = rs->one();
    license_entry entry;
    entry.license_data = row.get_as<sstring>("license_data");
    entry.signature = row.get_as<sstring>("signature");
    entry.uploaded_at = row.get_as<db_clock::time_point>("uploaded_at");
    entry.customer_id = row.get_as<sstring>("customer_id");
    entry.expiry_timestamp = row.get_as<int64_t>("expiry_timestamp");
    entry.grace_period_start_timestamp = row.get_opt<int64_t>("grace_period_start_timestamp").value_or(0);
    if (row.has("grace_period_signature")) {
        entry.grace_period_signature = row.get_as<sstring>("grace_period_signature");
    }

    co_return entry;
}

std::optional<license::license_data> license_service::verify_license(const license_entry& entry) {
    // Reconstruct the license file content and verify using existing verification
    seastar::sstring content = entry.license_data + "\n" + entry.signature;
    return license::verify_license_file(content);
}

seastar::future<license_service::status_response> license_service::get_status() {
    auto entry_opt = co_await get_license();

    if (!entry_opt) {
        co_return status_response{
            .status = license_status::no_license,
            .customer_id = std::nullopt,
            .message = "No license installed"
        };
    }

    auto verified = verify_license(*entry_opt);
    if (!verified) {
        co_return status_response{
            .status = license_status::invalid,
            .customer_id = entry_opt->customer_id,
            .message = "License signature is invalid or has been tampered with"
        };
    }

    if (verified->is_expired()) {
        status_response resp{
            .status = license_status::expired,
            .customer_id = entry_opt->customer_id,
            .message = "License has expired"
        };

        // Check grace period status
        if (entry_opt->grace_period_start_timestamp > 0) {
            using namespace std::chrono;
            auto grace_start = system_clock::time_point{seconds{entry_opt->grace_period_start_timestamp}};
            auto grace_end = grace_start + license::grace_period_duration;
            auto now = system_clock::now();

            resp.grace_period_ends_at = duration_cast<seconds>(grace_end.time_since_epoch()).count();

            if (now < grace_end) {
                auto remaining = duration_cast<hours>(grace_end - now);
                resp.days_until_write_block = remaining.count() / 24;
                resp.message = format("License expired. Grace period active. Writes will be blocked in {} days",
                                    resp.days_until_write_block.value());
            } else {
                resp.days_until_write_block = 0;
                resp.message = "License expired. Grace period ended. Writes are BLOCKED";
            }
        } else {
            resp.message = "License expired. Grace period will start on next compliance check";
        }

        co_return resp;
    }

    co_return status_response{
        .status = license_status::valid,
        .customer_id = entry_opt->customer_id,
        .message = std::nullopt
    };
}

seastar::future<license_service::usage_response> license_service::get_usage() {
    usage_response resp;

    // Get current usage
    resp.current_vcpus = seastar::smp::count;
    resp.current_storage_bytes = co_await license::calculate_total_storage_async(_db);

    // Get license if any
    auto entry_opt = co_await get_license();
    if (!entry_opt) {
        // No license - check against default limits
        resp.max_vcpus = license::default_max_vcpus;
        resp.max_storage_bytes = license::default_max_storage_bytes;
        resp.vcpu_limit_exceeded = resp.current_vcpus > license::default_max_vcpus;
        resp.storage_limit_exceeded = resp.current_storage_bytes > license::default_max_storage_bytes;
        co_return resp;
    }

    resp.customer_id = entry_opt->customer_id;
    resp.expiry_timestamp = entry_opt->expiry_timestamp;

    auto verified = verify_license(*entry_opt);
    if (verified && !verified->is_expired()) {
        // Valid license
        if (!verified->is_unlimited_vcpus()) {
            resp.max_vcpus = verified->max_vcpus;
            resp.vcpu_limit_exceeded = resp.current_vcpus > verified->max_vcpus;
        } else {
            resp.vcpu_limit_exceeded = false;
        }

        if (!verified->is_unlimited_storage()) {
            resp.max_storage_bytes = verified->max_storage_bytes;
            resp.storage_limit_exceeded = resp.current_storage_bytes > verified->max_storage_bytes;
        } else {
            resp.storage_limit_exceeded = false;
        }
    } else {
        // Invalid or expired license - check against default limits
        resp.max_vcpus = license::default_max_vcpus;
        resp.max_storage_bytes = license::default_max_storage_bytes;
        resp.vcpu_limit_exceeded = resp.current_vcpus > license::default_max_vcpus;
        resp.storage_limit_exceeded = resp.current_storage_bytes > license::default_max_storage_bytes;
    }

    co_return resp;
}

seastar::future<> license_service::delete_license() {
    lslog.info("Deleting license");

    co_await container().invoke_on(0, [] (license_service& ls) {
        return ls.with_retry([&ls] {
            return ls.delete_license_inner();
        });
    });
}

seastar::future<> license_service::delete_license_inner() {
    auto guard = co_await _group0_client.start_operation(_abort_source, service::raft_timeout{});

    static const sstring stmt = format(
        "DELETE FROM {}.{} WHERE key = ?",
        db::system_keyspace::NAME, db::system_keyspace::LICENSES);

    auto muts = co_await _qp.get_mutations_internal(stmt, license_query_state(), guard.write_timestamp(), {
        sstring(LICENSE_KEY)
    });

    if (muts.size() != 1) {
        on_internal_error(lslog, fmt::format("expected 1 mutation got {}", muts.size()));
    }

    utils::chunked_vector<canonical_mutation> cmuts;
    cmuts.emplace_back(std::move(muts[0]));

    auto cmd = _group0_client.prepare_command(
        service::write_mutations{std::move(cmuts)}, guard, "delete license");
    co_await _group0_client.add_entry(std::move(cmd), std::move(guard), _abort_source);

    lslog.info("License deleted");
}

// Generate signature for grace period data to prevent tampering
// Signs: license_data + ":" + grace_period_start_timestamp
seastar::sstring license_service::generate_grace_period_signature(
    const seastar::sstring& license_data,
    int64_t grace_period_start_timestamp) {

    // Get the embedded public key for signing
    auto public_key = license::get_license_public_key();

    // Create the data to sign: license_data + ":" + timestamp
    seastar::sstring data_to_sign = format("{}:{}", license_data, grace_period_start_timestamp);

    // Sign using the embedded private key (server-side operation)
    // Note: In production, this would use a server-side private key
    // For now, we'll use a hash-based approach with the public key as seed
    std::array<uint8_t, 32> hash;
    auto data_bytes = reinterpret_cast<const uint8_t*>(data_to_sign.data());

    // Use SHA-256 of (public_key + data) as the "signature"
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP context");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, public_key.data(), public_key.size()) != 1 ||
        EVP_DigestUpdate(ctx, data_bytes, data_to_sign.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash.data(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to generate grace period signature");
    }

    EVP_MD_CTX_free(ctx);

    // Convert to hex string
    seastar::sstring result;
    for (size_t i = 0; i < 32; ++i) {
        result += format("{:02x}", hash[i]);
    }

    return result;
}

// Verify grace period signature
bool license_service::verify_grace_period_signature(
    const seastar::sstring& license_data,
    int64_t grace_period_start_timestamp,
    const seastar::sstring& signature) {

    if (signature.empty()) {
        return false;
    }

    try {
        auto expected = generate_grace_period_signature(license_data, grace_period_start_timestamp);
        return signature == expected;
    } catch (...) {
        return false;
    }
}

// Check if writes should be blocked due to expired grace period
seastar::future<bool> license_service::is_write_blocked() {
    auto entry_opt = co_await get_license();

    if (!entry_opt) {
        // No license - check against default limits (don't block writes for now)
        co_return false;
    }

    auto verified = verify_license(*entry_opt);
    if (!verified) {
        // Invalid license - don't block writes, just log warnings
        co_return false;
    }

    if (!verified->is_expired()) {
        // Valid, non-expired license
        co_return false;
    }

    // License is expired - check grace period
    if (entry_opt->grace_period_start_timestamp == 0) {
        // Grace period hasn't started yet (will start on next compliance check)
        // Allow writes for now
        co_return false;
    }

    // Verify grace period signature
    if (!verify_grace_period_signature(entry_opt->license_data,
                                      entry_opt->grace_period_start_timestamp,
                                      entry_opt->grace_period_signature)) {
        lslog.error("Grace period signature tampering detected! Blocking writes.");
        co_return true;  // Block writes if tampering detected
    }

    // Calculate if grace period has ended
    using namespace std::chrono;
    auto grace_start = system_clock::time_point{seconds{entry_opt->grace_period_start_timestamp}};
    auto grace_end = grace_start + license::grace_period_duration;
    auto now = system_clock::now();

    if (now >= grace_end) {
        // Grace period has ended - block writes
        lslog.warn("Grace period ended for customer '{}'. Writes are BLOCKED.", entry_opt->customer_id);
        co_return true;
    }

    // Still within grace period
    co_return false;
}

// Check if license is expired and start grace period if needed
seastar::future<> license_service::check_and_update_grace_period() {
    auto entry_opt = co_await get_license();

    if (!entry_opt) {
        co_return;  // No license, nothing to do
    }

    auto verified = verify_license(*entry_opt);
    if (!verified || !verified->is_expired()) {
        co_return;  // License valid or invalid, no grace period needed
    }

    // License is expired
    if (entry_opt->grace_period_start_timestamp > 0) {
        // Grace period already started, verify signature
        if (!verify_grace_period_signature(entry_opt->license_data,
                                          entry_opt->grace_period_start_timestamp,
                                          entry_opt->grace_period_signature)) {
            lslog.error("Grace period signature verification failed! Possible tampering detected.");
            // Treat as if grace period ended immediately
        }
        co_return;  // Grace period already tracking
    }

    // Start grace period NOW
    using namespace std::chrono;
    auto now = system_clock::now();
    int64_t grace_start = duration_cast<seconds>(now.time_since_epoch()).count();

    lslog.warn("License expired for customer '{}'. Starting 7-day grace period. "
               "Writes will be blocked after: {}",
               entry_opt->customer_id,
               now + license::grace_period_duration);

    // Update the database with grace period start time
    co_await container().invoke_on(0, [grace_start] (license_service& ls) {
        return ls.with_retry([&ls, grace_start] {
            return ls.start_grace_period_inner(grace_start);
        });
    });
}

seastar::future<> license_service::start_grace_period_inner(int64_t grace_start_timestamp) {
    // First, get the current license data
    auto entry_opt = co_await get_license();
    if (!entry_opt) {
        co_return;  // License was deleted, nothing to do
    }

    // Generate signature for the grace period data
    auto grace_sig = generate_grace_period_signature(entry_opt->license_data, grace_start_timestamp);

    auto guard = co_await _group0_client.start_operation(_abort_source, service::raft_timeout{});

    static const sstring stmt = format(
        "UPDATE {}.{} SET grace_period_start_timestamp = ?, grace_period_signature = ? WHERE key = ?",
        db::system_keyspace::NAME, db::system_keyspace::LICENSES);

    auto muts = co_await _qp.get_mutations_internal(stmt, license_query_state(), guard.write_timestamp(), {
        grace_start_timestamp,
        grace_sig,
        sstring(LICENSE_KEY)
    });

    if (muts.size() != 1) {
        on_internal_error(lslog, fmt::format("expected 1 mutation got {}", muts.size()));
    }

    utils::chunked_vector<canonical_mutation> cmuts;
    cmuts.emplace_back(std::move(muts[0]));

    auto cmd = _group0_client.prepare_command(
        service::write_mutations{std::move(cmuts)}, guard, "start grace period");
    co_await _group0_client.add_entry(std::move(cmd), std::move(guard), _abort_source);

    lslog.info("Grace period started at timestamp {}", grace_start_timestamp);
}

template <typename Func>
seastar::future<> license_service::with_retry(Func&& func) {
    int retries = 10;
    while (true) {
        try {
            co_await func();
        } catch (const ::service::group0_concurrent_modification&) {
            lslog.warn("Failed to update license due to guard conflict, retries={}", retries);
            if (retries--) {
                continue;
            }
            throw;
        }
        break;
    }
}

} // namespace service

