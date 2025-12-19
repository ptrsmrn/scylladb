/*
 * Copyright (C) 2024-present ScyllaDB
 */

/*
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

#include "license_compliance.hh"

#include <cstring>
#include <sstream>
#include <iomanip>

#include <seastar/core/smp.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/file.hh>
#include <seastar/util/file.hh>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <fmt/format.h>

#include "replica/database.hh"
#include "service/raft/raft_group_registry.hh"
#include "utils/log.hh"
#include "utils/assert.hh"

using namespace std::chrono_literals;

static logging::logger lclog("license");

namespace license {

namespace {

// ============================================================================
// Public Key Derivation (Obfuscation)
// ============================================================================
// The public key is XORed with values derived from a deterministic PRNG.
// This makes it harder to find and modify in the binary.

constexpr uint8_t derive_byte(size_t pos, uint64_t salt) {
    uint64_t v = (pos * 0x9E3779B97F4A7C15ULL) ^ salt;
    v ^= v >> 33;
    v *= 0xFF51AFD7ED558CCDULL;
    v ^= v >> 33;
    v *= 0xC4CEB9FE1A85EC53ULL;
    v ^= v >> 33;
    return static_cast<uint8_t>(v & 0xFF);
}

// The obfuscated public key base values.
// To generate these for a new keypair:
// 1. Generate a keypair with generate_keypair()
// 2. Call print_keypair_for_embedding() to get these values
// 3. Replace these constants
//
// Current values are for a TEST keypair - replace for production!
constexpr std::array<uint8_t, 32> obfuscated_pubkey_base = {
    0x8a, 0x3d, 0x7e, 0x21, 0xf4, 0x56, 0x9b, 0xc8,
    0x12, 0xe7, 0x4a, 0xbd, 0x03, 0x68, 0xdf, 0x91,
    0x5c, 0xa2, 0x37, 0xe9, 0x84, 0x1b, 0x6f, 0xc0,
    0xd5, 0x49, 0x8e, 0x22, 0xb7, 0x60, 0xf3, 0x0c
};

constexpr uint64_t pubkey_salt = 0x5C411A2024DB01F5ULL;

std::array<uint8_t, ed25519_public_key_size> compute_public_key() {
    std::array<uint8_t, ed25519_public_key_size> pubkey;
    for (size_t i = 0; i < ed25519_public_key_size; ++i) {
        pubkey[i] = obfuscated_pubkey_base[i] ^ derive_byte(i, pubkey_salt);
    }
    return pubkey;
}

// ============================================================================
// Hex Conversion Utilities
// ============================================================================

int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

char int_to_hex_char(int v) {
    static const char hex_chars[] = "0123456789abcdef";
    return hex_chars[v & 0xf];
}

seastar::sstring bytes_to_hex(const uint8_t* data, size_t len) {
    seastar::sstring result;
    result.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result[i * 2] = int_to_hex_char(data[i] >> 4);
        result[i * 2 + 1] = int_to_hex_char(data[i] & 0xf);
    }
    return result;
}

std::optional<std::vector<uint8_t>> hex_to_bytes(const seastar::sstring& hex) {
    if (hex.size() % 2 != 0) return std::nullopt;

    std::vector<uint8_t> result(hex.size() / 2);
    for (size_t i = 0; i < result.size(); ++i) {
        int high = hex_char_to_int(hex[i * 2]);
        int low = hex_char_to_int(hex[i * 2 + 1]);
        if (high < 0 || low < 0) return std::nullopt;
        result[i] = static_cast<uint8_t>((high << 4) | low);
    }
    return result;
}

// ============================================================================
// String Utilities
// ============================================================================

seastar::sstring trim(const seastar::sstring& s) {
    if (s.empty()) return "";

    size_t start = 0;
    while (start < s.size() && (s[start] == ' ' || s[start] == '\t' ||
                                 s[start] == '\n' || s[start] == '\r')) {
        ++start;
    }

    if (start == s.size()) return "";

    size_t end = s.size() - 1;
    while (end > start && (s[end] == ' ' || s[end] == '\t' ||
                           s[end] == '\n' || s[end] == '\r')) {
        --end;
    }

    return s.substr(start, end - start + 1);
}

std::vector<seastar::sstring> split(const seastar::sstring& s, char delim) {
    std::vector<seastar::sstring> result;
    size_t start = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == delim) {
            result.push_back(s.substr(start, i - start));
            start = i + 1;
        }
    }
    result.push_back(s.substr(start));
    return result;
}

} // anonymous namespace

// ============================================================================
// license_data Implementation
// ============================================================================

seastar::sstring license_data::serialize() const {
    // Format: SCYLLA_LICENSE:v1:<customer_id>:<expiry>:<max_vcpus>:<max_storage_tb>
    int64_t storage_tb = (max_storage_bytes == unlimited_storage) ? 0 :
                         max_storage_bytes / (int64_t(1024) * 1024 * 1024 * 1024);
    uint64_t expiry_ts = never_expires() ? 0 :
                         std::chrono::duration_cast<std::chrono::seconds>(
                             expiry.time_since_epoch()).count();

    return fmt::format("SCYLLA_LICENSE:v1:{}:{}:{}:{}",
                       customer_id, expiry_ts, max_vcpus, storage_tb);
}

std::optional<license_data> license_data::parse(const seastar::sstring& data) {
    auto parts = split(data, ':');
    if (parts.size() != 6) return std::nullopt;

    if (parts[0] != "SCYLLA_LICENSE" || parts[1] != "v1") {
        return std::nullopt;
    }

    license_data result;
    result.customer_id = parts[2];

    if (result.customer_id.empty() || result.customer_id.size() > 64) {
        return std::nullopt;
    }

    try {
        // parts[3] is expiry_timestamp
        unsigned long long expiry_ts = std::stoull(std::string(parts[3].data(), parts[3].size()));
        if (expiry_ts == 0) {
            result.expiry = std::chrono::system_clock::time_point{};
        } else {
            result.expiry = std::chrono::system_clock::time_point{
                std::chrono::seconds{expiry_ts}};
        }

        // parts[4] is max_vcpus
        unsigned long vcpus = std::stoul(std::string(parts[4].data(), parts[4].size()));
        result.max_vcpus = static_cast<unsigned>(vcpus);

        // parts[5] is max_storage_tb
        long long storage_tb = std::stoll(std::string(parts[5].data(), parts[5].size()));
        result.max_storage_bytes = (storage_tb == 0) ? unlimited_storage :
                                   storage_tb * int64_t(1024) * 1024 * 1024 * 1024;
    } catch (...) {
        return std::nullopt;
    }

    return result;
}

// ============================================================================
// Key Generation
// ============================================================================

keypair generate_keypair() {
    std::array<uint8_t, ed25519_seed_size> seed;
    if (RAND_bytes(seed.data(), seed.size()) != 1) {
        throw std::runtime_error("Failed to generate random seed");
    }
    return generate_keypair_from_seed(seed);
}

keypair generate_keypair_from_seed(const std::array<uint8_t, ed25519_seed_size>& seed) {
    keypair kp;
    kp.seed = seed;

    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());

    if (!pkey) {
        throw std::runtime_error("Failed to create keypair from seed");
    }

    // Extract public key
    size_t pubkey_len = ed25519_public_key_size;
    if (EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pubkey_len) != 1) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to extract public key");
    }

    // Build private key (seed + public key in our representation)
    std::copy(seed.begin(), seed.end(), kp.private_key.begin());
    std::copy(kp.public_key.begin(), kp.public_key.end(),
              kp.private_key.begin() + ed25519_seed_size);

    EVP_PKEY_free(pkey);
    return kp;
}

// ============================================================================
// License Generation
// ============================================================================

seastar::sstring generate_license(
    const std::array<uint8_t, ed25519_private_key_size>& private_key,
    const license_data& data) {

    seastar::sstring license_string = data.serialize();

    // Create signing key from the seed (first 32 bytes of private_key)
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr, private_key.data(), ed25519_seed_size);

    if (!pkey) {
        throw std::runtime_error("Failed to create signing key");
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create signing context");
    }

    std::array<uint8_t, ed25519_signature_size> signature;
    size_t sig_len = signature.size();

    bool success = false;
    if (EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        if (EVP_DigestSign(md_ctx, signature.data(), &sig_len,
                          reinterpret_cast<const unsigned char*>(license_string.data()),
                          license_string.size()) == 1) {
            success = true;
        }
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    if (!success) {
        throw std::runtime_error("Failed to sign license");
    }

    // Format: data\nsignature_hex
    return license_string + "\n" + bytes_to_hex(signature.data(), signature.size());
}

// ============================================================================
// License Verification
// ============================================================================

std::array<uint8_t, ed25519_public_key_size> get_license_public_key() {
    return compute_public_key();
}

std::optional<license_data> verify_license_file(const seastar::sstring& content) {
    // Split into lines
    auto lines = split(trim(content), '\n');
    if (lines.size() != 2) {
        lclog.debug("License file must have exactly 2 lines");
        return std::nullopt;
    }

    seastar::sstring license_string = trim(lines[0]);
    seastar::sstring signature_hex = trim(lines[1]);

    // Parse signature
    if (signature_hex.size() != ed25519_signature_size * 2) {
        lclog.debug("Invalid signature length: {} (expected {})",
                   signature_hex.size(), ed25519_signature_size * 2);
        return std::nullopt;
    }

    auto sig_bytes = hex_to_bytes(signature_hex);
    if (!sig_bytes || sig_bytes->size() != ed25519_signature_size) {
        lclog.debug("Invalid signature hex encoding");
        return std::nullopt;
    }

    // Verify signature
    auto pubkey = get_license_public_key();

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr, pubkey.data(), pubkey.size());

    if (!pkey) {
        lclog.debug("Failed to create public key for verification");
        return std::nullopt;
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        return std::nullopt;
    }

    bool valid = false;
    if (EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        int result = EVP_DigestVerify(
            md_ctx,
            sig_bytes->data(),
            sig_bytes->size(),
            reinterpret_cast<const unsigned char*>(license_string.data()),
            license_string.size()
        );
        valid = (result == 1);
    }

    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);

    if (!valid) {
        lclog.debug("License signature verification failed");
        return std::nullopt;
    }

    // Parse the license data
    auto data = license_data::parse(license_string);
    if (!data) {
        lclog.debug("Failed to parse license data");
        return std::nullopt;
    }

    // Check expiration
    if (data->is_expired()) {
        lclog.warn("License for customer '{}' has expired", data->customer_id);
        return std::nullopt;
    }

    lclog.info("Valid license detected for customer '{}' (vcpus: {}, storage: {} TB)",
               data->customer_id,
               data->is_unlimited_vcpus() ? "unlimited" : std::to_string(data->max_vcpus),
               data->is_unlimited_storage() ? "unlimited" :
                   std::to_string(data->max_storage_bytes / (int64_t(1024) * 1024 * 1024 * 1024)));

    return data;
}

seastar::future<std::optional<license_data>> verify_license_file_async(
    const std::filesystem::path& license_path) {
    try {
        bool exists = co_await seastar::file_exists(license_path.native());
        if (!exists) {
            lclog.debug("License file not found: {}", license_path.native());
            co_return std::nullopt;
        }

        seastar::sstring content;
        try {
            content = co_await seastar::util::read_entire_file_contiguous(license_path);
        } catch (const std::exception& e) {
            lclog.warn("Failed to read license file {}: {}", license_path.native(), e.what());
            co_return std::nullopt;
        }

        co_return verify_license_file(content);
    } catch (const std::exception& e) {
        lclog.warn("Error checking license file: {}", e.what());
        co_return std::nullopt;
    }
}

// ============================================================================
// Compliance Checking
// ============================================================================

seastar::future<int64_t> calculate_total_storage_async(seastar::sharded<replica::database>& db) {
    return db.map_reduce0(
        [] (replica::database& local_db) {
            int64_t total = 0;
            local_db.get_tables_metadata().for_each_table([&total] (table_id, lw_shared_ptr<replica::table> table) {
                total += table->get_stats().live_disk_space_used.on_disk;
            });
            return total;
        },
        int64_t(0),
        std::plus<int64_t>()
    );
}

seastar::future<compliance_status> check_compliance_async(
    seastar::sharded<replica::database>& db,
    const std::filesystem::path& license_path,
    const limits& default_lim) {

    compliance_status status;

    // Check for a valid license file first
    auto license_opt = co_await verify_license_file_async(license_path);

    if (license_opt) {
        status.has_valid_license = true;
        status.license_info = *license_opt;
        status.license_expired = license_opt->is_expired();

        if (status.license_expired) {
            status.has_valid_license = false;
        }
    }

    // Get current resource usage
    status.current_vcpus = seastar::smp::count;

    status.current_storage_bytes = co_await db.map_reduce0(
        [] (replica::database& local_db) {
            int64_t total = 0;
            local_db.get_tables_metadata().for_each_table([&total] (table_id, lw_shared_ptr<replica::table> table) {
                total += table->get_stats().live_disk_space_used.on_disk;
            });
            return total;
        },
        int64_t(0),
        std::plus<int64_t>()
    );

    // Determine effective limits
    limits effective_lim = default_lim;

    if (status.has_valid_license && status.license_info) {
        // Use license-specified limits
        if (!status.license_info->is_unlimited_vcpus()) {
            effective_lim.max_vcpus = status.license_info->max_vcpus;
        } else {
            effective_lim.max_vcpus = unlimited_vcpus;
        }

        if (!status.license_info->is_unlimited_storage()) {
            effective_lim.max_storage_bytes = status.license_info->max_storage_bytes;
        } else {
            effective_lim.max_storage_bytes = unlimited_storage;
        }
    }

    // Check limits (only if not unlimited)
    if (effective_lim.max_vcpus != unlimited_vcpus) {
        status.vcpu_limit_exceeded = status.current_vcpus > effective_lim.max_vcpus;
    }

    if (effective_lim.max_storage_bytes != unlimited_storage) {
        status.storage_limit_exceeded = status.current_storage_bytes > effective_lim.max_storage_bytes;
    }

    co_return status;
}

compliance_status check_compliance(seastar::sharded<replica::database>& db,
                                   const std::filesystem::path& license_path,
                                   const limits& default_lim) {
    return check_compliance_async(db, license_path, default_lim).get();
}

void log_compliance_warning(const compliance_status& status, const limits& lim) {
    if (status.is_compliant()) {
        return;
    }

    if (status.license_expired) {
        lclog.warn("================================================================================");
        lclog.warn("LICENSE WARNING: Your ScyllaDB license has EXPIRED");
        lclog.warn("================================================================================");
        if (status.license_info) {
            lclog.warn("  Customer: {}", status.license_info->customer_id);
        }
        lclog.warn("");
        lclog.warn("Please contact ScyllaDB to renew your license:");
        lclog.warn("  https://www.scylladb.com/contact/");
        lclog.warn("================================================================================");
        return;
    }

    lclog.warn("================================================================================");
    lclog.warn("LICENSE WARNING: Your usage exceeds the ScyllaDB Source Available License limits");
    lclog.warn("================================================================================");

    if (status.vcpu_limit_exceeded) {
        lclog.warn("  VCPU limit exceeded: using {} VCPUs (limit: {})",
                   status.current_vcpus, lim.max_vcpus);
    }

    if (status.storage_limit_exceeded) {
        auto current_tb = static_cast<double>(status.current_storage_bytes) /
                          (1024.0 * 1024.0 * 1024.0 * 1024.0);
        auto max_tb = static_cast<double>(lim.max_storage_bytes) /
                      (1024.0 * 1024.0 * 1024.0 * 1024.0);
        lclog.warn("  Storage limit exceeded: using {:.2f} TB (limit: {:.0f} TB)",
                   current_tb, max_tb);
    }

    lclog.warn("");
    lclog.warn("To comply with the license, you must either:");
    lclog.warn("  1. Reduce your resource usage to within the license limits, or");
    lclog.warn("  2. Purchase a commercial license from ScyllaDB");
    lclog.warn("");
    lclog.warn("For more information about commercial licensing, visit:");
    lclog.warn("  https://www.scylladb.com/scylladb-proprietary-software-license-agreement/");
    lclog.warn("================================================================================");
}

// ============================================================================
// Utility Functions
// ============================================================================

void print_keypair_for_embedding(const keypair& kp) {
    fmt::print("// Ed25519 Keypair Information\n");
    fmt::print("// ============================\n\n");

    fmt::print("// Seed (KEEP SECRET - store securely offline):\n");
    fmt::print("// {}\n\n", bytes_to_hex(kp.seed.data(), kp.seed.size()));

    fmt::print("// Public key (raw bytes):\n");
    fmt::print("// {}\n\n", bytes_to_hex(kp.public_key.data(), kp.public_key.size()));

    fmt::print("// Obfuscated public key base (for embedding in code):\n");
    fmt::print("// XOR with derive_byte(i, 0x5C411A2024DB01F5ULL)\n");
    fmt::print("constexpr std::array<uint8_t, 32> obfuscated_pubkey_base = {{\n    ");
    for (size_t i = 0; i < kp.public_key.size(); ++i) {
        uint8_t obfuscated = kp.public_key[i] ^ derive_byte(i, pubkey_salt);
        fmt::print("0x{:02x}", obfuscated);
        if (i < kp.public_key.size() - 1) {
            fmt::print(", ");
            if ((i + 1) % 8 == 0) fmt::print("\n    ");
        }
    }
    fmt::print("\n}};\n\n");

    fmt::print("// To generate a license with this keypair:\n");
    fmt::print("// auto kp = license::generate_keypair_from_seed(seed);\n");
    fmt::print("// auto lic = license::generate_license(kp.private_key, data);\n");
}

// ============================================================================
// compliance_monitor Implementation
// ============================================================================

compliance_monitor::compliance_monitor(seastar::abort_source& as,
                                       seastar::sharded<replica::database>& db)
    : compliance_monitor(as, db, config{})
{
}

compliance_monitor::compliance_monitor(seastar::abort_source& as,
                                       seastar::sharded<replica::database>& db,
                                       config cfg)
    : _as_sub(as.subscribe([this] () noexcept {
        _as.request_abort();
        _check_cv.broadcast();
    }))
    , _db(db)
    , _raft_gr(nullptr)
    , _cfg(std::move(cfg))
{
}

compliance_monitor::compliance_monitor(seastar::abort_source& as,
                                       seastar::sharded<replica::database>& db,
                                       seastar::sharded<service::raft_group_registry>& raft_gr,
                                       config cfg)
    : _as_sub(as.subscribe([this] () noexcept {
        _as.request_abort();
        _check_cv.broadcast();
    }))
    , _db(db)
    , _raft_gr(&raft_gr)
    , _cfg(std::move(cfg))
{
}

compliance_monitor::~compliance_monitor() {
    SCYLLA_ASSERT(_check_loop_fut.available());
}

seastar::future<> compliance_monitor::start() {
    co_await do_check();
    _check_loop_fut = run_check_loop();
}

seastar::future<> compliance_monitor::stop() noexcept {
    _as.request_abort();
    _check_cv.broadcast();
    return std::exchange(_check_loop_fut, seastar::make_ready_future<>());
}

void compliance_monitor::trigger_check() noexcept {
    _check_cv.broadcast();
}

bool compliance_monitor::should_skip_check() const noexcept {
    // If no raft_group_registry is configured, run checks on all nodes (legacy behavior)
    if (!_raft_gr) {
        return false;
    }

    // Only run on shard 0 where group0 is managed
    if (seastar::this_shard_id() != 0) {
        return true;
    }

    // Check if group0 is alive and we are the leader
    try {
        auto& raft_gr = _raft_gr->local();
        if (!raft_gr.is_group0_alive()) {
            // Group0 not ready yet, skip check for now
            // Will check again on next interval
            return true;
        }

        auto& group0 = raft_gr.group0();
        if (!group0.is_leader()) {
            // Not the leader, skip check
            lclog.trace("License check skipped: not the Raft group0 leader");
            return true;
        }
    } catch (...) {
        // If we can't determine leader status, skip to be safe
        lclog.trace("License check skipped: unable to determine Raft leader status");
        return true;
    }

    return false;
}

bool compliance_monitor::is_check_node() const noexcept {
    return !should_skip_check();
}

seastar::future<> compliance_monitor::run_check_loop() {
    try {
        while (!_as.abort_requested()) {
            try {
                co_await _check_cv.wait(_cfg.check_interval);
            } catch (const seastar::condition_variable_timed_out&) {
                // Expected - time for periodic check
            }

            if (_as.abort_requested()) {
                break;
            }

            co_await do_check();
        }
    } catch (const seastar::sleep_aborted&) {
        // Normal shutdown
    } catch (const seastar::abort_requested_exception&) {
        // Normal shutdown
    } catch (...) {
        lclog.error("License compliance check loop exited with error: {}",
                   std::current_exception());
    }
}

seastar::future<> compliance_monitor::do_check() {
    // Only perform the check on the Raft leader node to avoid redundant load
    if (should_skip_check()) {
        co_return;
    }

    lclog.debug("License compliance check: running on leader node");

    auto new_status = co_await check_compliance_async(_db, _cfg.license_file_path,
                                                       _cfg.default_limits);

    bool was_compliant = _last_status.is_compliant();
    bool is_now_compliant = new_status.is_compliant();

    _last_status = new_status;

    if (!is_now_compliant) {
        bool status_changed = was_compliant || !_warning_logged;

        if (status_changed) {
            log_compliance_warning(new_status, _cfg.default_limits);
            _warning_logged = true;
        }

        lclog.debug("License compliance check: non-compliant (storage: {} bytes, vcpus: {})",
                   new_status.current_storage_bytes, new_status.current_vcpus);
    } else {
        if (_warning_logged) {
            lclog.info("License compliance restored");
        }
        _warning_logged = false;

        if (new_status.has_valid_license && new_status.license_info) {
            lclog.debug("License compliance check: licensed customer '{}'",
                       new_status.license_info->customer_id);
        } else {
            lclog.debug("License compliance check: compliant (storage: {} bytes, vcpus: {})",
                       new_status.current_storage_bytes, new_status.current_vcpus);
        }
    }
}

} // namespace license
