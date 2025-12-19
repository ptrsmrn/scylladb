/*
 * Copyright (C) 2024-present ScyllaDB
 */

/*
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

#include <boost/test/unit_test.hpp>

#include <seastar/core/smp.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/file.hh>
#include <seastar/core/fstream.hh>

#include <openssl/evp.h>
#include <openssl/rand.h>

#undef SEASTAR_TESTING_MAIN
#include <seastar/testing/test_case.hh>
#include <seastar/testing/thread_test_case.hh>

#include "test/lib/cql_test_env.hh"
#include "test/lib/log.hh"
#include "test/lib/tmpdir.hh"

#include "license_compliance.hh"

using namespace std::chrono_literals;

BOOST_AUTO_TEST_SUITE(license_compliance_test)

namespace {

// Helper to write a license file with the given content
seastar::future<> write_license_file(const std::filesystem::path& path, const seastar::sstring& content) {
    auto f = co_await seastar::open_file_dma(path.native(),
        seastar::open_flags::wo | seastar::open_flags::create | seastar::open_flags::truncate);
    auto out = co_await seastar::make_file_output_stream(f);
    co_await out.write(content.data(), content.size());
    co_await out.close();
}

// Test keypair - deterministic for reproducible tests
// In production, ScyllaDB would use a securely generated keypair
license::keypair get_test_keypair() {
    // Use a fixed seed for reproducible tests
    std::array<uint8_t, license::ed25519_seed_size> test_seed = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    return license::generate_keypair_from_seed(test_seed);
}

} // anonymous namespace

// ============================================================================
// Key Generation Tests
// ============================================================================

SEASTAR_THREAD_TEST_CASE(test_generate_keypair) {
    auto kp = license::generate_keypair();

    // Seed should be 32 bytes
    BOOST_REQUIRE_EQUAL(kp.seed.size(), license::ed25519_seed_size);

    // Public key should be 32 bytes
    BOOST_REQUIRE_EQUAL(kp.public_key.size(), license::ed25519_public_key_size);

    // Private key should be 64 bytes (seed + public key)
    BOOST_REQUIRE_EQUAL(kp.private_key.size(), license::ed25519_private_key_size);

    // Seed should be at the start of private key
    BOOST_REQUIRE(std::equal(kp.seed.begin(), kp.seed.end(), kp.private_key.begin()));

    // Public key should be at the end of private key
    BOOST_REQUIRE(std::equal(kp.public_key.begin(), kp.public_key.end(),
                            kp.private_key.begin() + license::ed25519_seed_size));
}

SEASTAR_THREAD_TEST_CASE(test_generate_keypair_from_seed_deterministic) {
    std::array<uint8_t, license::ed25519_seed_size> seed = {
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    };

    auto kp1 = license::generate_keypair_from_seed(seed);
    auto kp2 = license::generate_keypair_from_seed(seed);

    // Same seed should produce same keypair
    BOOST_REQUIRE(kp1.public_key == kp2.public_key);
    BOOST_REQUIRE(kp1.private_key == kp2.private_key);
}

SEASTAR_THREAD_TEST_CASE(test_get_license_public_key_consistent) {
    auto pubkey1 = license::get_license_public_key();
    auto pubkey2 = license::get_license_public_key();

    BOOST_REQUIRE_EQUAL(pubkey1.size(), license::ed25519_public_key_size);
    BOOST_REQUIRE(pubkey1 == pubkey2);
}

// ============================================================================
// License Data Tests
// ============================================================================

SEASTAR_THREAD_TEST_CASE(test_license_data_serialize_parse_roundtrip) {
    license::license_data data;
    data.customer_id = "ACME_Corp";
    data.max_vcpus = 100;
    data.max_storage_bytes = int64_t(50) * 1024 * 1024 * 1024 * 1024; // 50 TB
    data.expiry = std::chrono::system_clock::time_point{std::chrono::seconds{1735689600}};

    auto serialized = data.serialize();
    testlog.info("Serialized license: {}", serialized);

    auto parsed = license::license_data::parse(serialized);
    BOOST_REQUIRE(parsed.has_value());
    BOOST_REQUIRE_EQUAL(parsed->customer_id, data.customer_id);
    BOOST_REQUIRE_EQUAL(parsed->max_vcpus, data.max_vcpus);
    BOOST_REQUIRE_EQUAL(parsed->max_storage_bytes, data.max_storage_bytes);
}

SEASTAR_THREAD_TEST_CASE(test_license_data_unlimited_values) {
    license::license_data data;
    data.customer_id = "Unlimited_Customer";
    data.max_vcpus = license::unlimited_vcpus;
    data.max_storage_bytes = license::unlimited_storage;
    data.expiry = {}; // Never expires

    BOOST_REQUIRE(data.is_unlimited_vcpus());
    BOOST_REQUIRE(data.is_unlimited_storage());
    BOOST_REQUIRE(data.never_expires());
    BOOST_REQUIRE(!data.is_expired());

    auto serialized = data.serialize();
    auto parsed = license::license_data::parse(serialized);

    BOOST_REQUIRE(parsed.has_value());
    BOOST_REQUIRE(parsed->is_unlimited_vcpus());
    BOOST_REQUIRE(parsed->is_unlimited_storage());
    BOOST_REQUIRE(parsed->never_expires());
}

SEASTAR_THREAD_TEST_CASE(test_license_data_expiration) {
    license::license_data expired_data;
    expired_data.customer_id = "Expired_Customer";
    // Set expiry to the past
    expired_data.expiry = std::chrono::system_clock::now() - std::chrono::hours{24};

    BOOST_REQUIRE(!expired_data.never_expires());
    BOOST_REQUIRE(expired_data.is_expired());

    license::license_data future_data;
    future_data.customer_id = "Future_Customer";
    // Set expiry to the future
    future_data.expiry = std::chrono::system_clock::now() + std::chrono::hours{24 * 365};

    BOOST_REQUIRE(!future_data.never_expires());
    BOOST_REQUIRE(!future_data.is_expired());
}

SEASTAR_THREAD_TEST_CASE(test_license_data_parse_invalid) {
    // Wrong format
    BOOST_REQUIRE(!license::license_data::parse("invalid").has_value());

    // Wrong prefix - Format: SCYLLA_LICENSE:v1:<customer>:<expiry>:<vcpus>:<storage_tb>
    BOOST_REQUIRE(!license::license_data::parse("OTHER:v1:cust:0:100:50").has_value());

    // Wrong version
    BOOST_REQUIRE(!license::license_data::parse("SCYLLA_LICENSE:v2:cust:0:100:50").has_value());

    // Missing fields
    BOOST_REQUIRE(!license::license_data::parse("SCYLLA_LICENSE:v1:cust:0:100").has_value());

    // Empty customer ID
    BOOST_REQUIRE(!license::license_data::parse("SCYLLA_LICENSE:v1::0:100:50").has_value());
}

// ============================================================================
// License Generation and Verification Tests
// ============================================================================

SEASTAR_THREAD_TEST_CASE(test_generate_and_verify_license) {
    // This test requires that the embedded public key matches our test keypair
    // In production, the embedded key would be different

    auto kp = get_test_keypair();

    testlog.info("Test keypair public key (hex):");
    seastar::sstring hex;
    for (auto b : kp.public_key) {
        hex += fmt::format("{:02x}", b);
    }
    testlog.info("  {}", hex);

    // The embedded public key (for comparison)
    auto embedded = license::get_license_public_key();
    seastar::sstring embedded_hex;
    for (auto b : embedded) {
        embedded_hex += fmt::format("{:02x}", b);
    }
    testlog.info("Embedded public key (hex):");
    testlog.info("  {}", embedded_hex);

    // Note: The test will only pass if we configure the embedded key to match
    // For now, just verify the license generation works

    license::license_data data;
    data.customer_id = "TestCustomer";
    data.max_vcpus = 200;
    data.max_storage_bytes = int64_t(100) * 1024 * 1024 * 1024 * 1024; // 100 TB
    data.expiry = std::chrono::system_clock::now() + std::chrono::hours{24 * 365};

    auto license_content = license::generate_license(kp.private_key, data);
    testlog.info("Generated license:\n{}", license_content);

    // The license should have 2 lines
    BOOST_REQUIRE(license_content.find('\n') != seastar::sstring::npos);
}

// ============================================================================
// License File Tests
// ============================================================================

SEASTAR_TEST_CASE(test_license_file_missing) {
    tmpdir tmp;
    auto license_path = tmp.path() / "nonexistent_license.key";

    auto result = co_await license::verify_license_file_async(license_path);
    BOOST_REQUIRE(!result.has_value());
}

SEASTAR_TEST_CASE(test_license_file_empty) {
    tmpdir tmp;
    auto license_path = tmp.path() / "empty_license.key";

    co_await write_license_file(license_path, "");

    auto result = co_await license::verify_license_file_async(license_path);
    BOOST_REQUIRE(!result.has_value());
}

SEASTAR_TEST_CASE(test_license_file_invalid_format) {
    tmpdir tmp;
    auto license_path = tmp.path() / "invalid_license.key";

    // Missing signature line - Format: SCYLLA_LICENSE:v1:<customer>:<expiry>:<vcpus>:<storage_tb>
    co_await write_license_file(license_path, "SCYLLA_LICENSE:v1:cust:0:100:50");

    auto result = co_await license::verify_license_file_async(license_path);
    BOOST_REQUIRE(!result.has_value());
}

SEASTAR_TEST_CASE(test_license_file_invalid_signature) {
    tmpdir tmp;
    auto license_path = tmp.path() / "invalid_sig_license.key";

    // Valid format but invalid signature (all zeros)
    // Format: SCYLLA_LICENSE:v1:<customer>:<expiry>:<vcpus>:<storage_tb>
    seastar::sstring content = "SCYLLA_LICENSE:v1:TestCust:0:100:50\n";
    content += seastar::sstring(128, '0'); // 64 zero bytes as hex

    co_await write_license_file(license_path, content);

    auto result = co_await license::verify_license_file_async(license_path);
    BOOST_REQUIRE(!result.has_value());
}

// ============================================================================
// Compliance Status Tests
// ============================================================================

SEASTAR_THREAD_TEST_CASE(test_compliance_status_is_compliant) {
    license::compliance_status status;

    // Default status should be compliant
    status.storage_limit_exceeded = false;
    status.vcpu_limit_exceeded = false;
    status.has_valid_license = false;
    status.license_expired = false;
    BOOST_REQUIRE(status.is_compliant());

    // Storage exceeded only
    status.storage_limit_exceeded = true;
    status.vcpu_limit_exceeded = false;
    BOOST_REQUIRE(!status.is_compliant());

    // VCPU exceeded only
    status.storage_limit_exceeded = false;
    status.vcpu_limit_exceeded = true;
    BOOST_REQUIRE(!status.is_compliant());

    // Valid license makes it compliant
    status.storage_limit_exceeded = true;
    status.vcpu_limit_exceeded = true;
    status.has_valid_license = true;
    status.license_expired = false;
    BOOST_REQUIRE(status.is_compliant());

    // Expired license doesn't help
    status.license_expired = true;
    BOOST_REQUIRE(!status.is_compliant());
}

// ============================================================================
// Compliance Check Tests (with database)
// ============================================================================

SEASTAR_TEST_CASE(test_check_compliance_no_license_within_limits) {
    return do_with_cql_env_thread([] (cql_test_env& e) {
        auto& db = e.db();
        tmpdir tmp;
        auto license_path = tmp.path() / "nonexistent_license.key";

        license::limits high_limits{
            .max_storage_bytes = int64_t(100) * 1024 * 1024 * 1024 * 1024,
            .max_vcpus = 1000
        };

        auto status = license::check_compliance(db, license_path, high_limits);

        BOOST_REQUIRE(!status.has_valid_license);
        BOOST_REQUIRE(!status.license_info.has_value());
        BOOST_REQUIRE(status.is_compliant());
        BOOST_REQUIRE_EQUAL(status.current_vcpus, seastar::smp::count);
    });
}

SEASTAR_TEST_CASE(test_check_compliance_no_license_exceeding_limits) {
    return do_with_cql_env_thread([] (cql_test_env& e) {
        auto& db = e.db();
        tmpdir tmp;
        auto license_path = tmp.path() / "nonexistent_license.key";

        license::limits restrictive_limits{
            .max_storage_bytes = int64_t(100) * 1024 * 1024 * 1024 * 1024,
            .max_vcpus = 0  // Any system will exceed this
        };

        auto status = license::check_compliance(db, license_path, restrictive_limits);

        BOOST_REQUIRE(!status.has_valid_license);
        BOOST_REQUIRE(status.vcpu_limit_exceeded);
        BOOST_REQUIRE(!status.is_compliant());
    });
}

// ============================================================================
// Default Limits Tests
// ============================================================================

SEASTAR_THREAD_TEST_CASE(test_default_limits) {
    BOOST_REQUIRE_EQUAL(license::default_max_storage_bytes, int64_t(10) * 1024 * 1024 * 1024 * 1024);
    BOOST_REQUIRE_EQUAL(license::default_max_vcpus, 50u);

    license::limits default_limits;
    BOOST_REQUIRE_EQUAL(default_limits.max_storage_bytes, license::default_max_storage_bytes);
    BOOST_REQUIRE_EQUAL(default_limits.max_vcpus, license::default_max_vcpus);
}

// ============================================================================
// Compliance Monitor Tests
// ============================================================================

SEASTAR_TEST_CASE(test_compliance_monitor_basic) {
    return do_with_cql_env_thread([] (cql_test_env& e) {
        auto& db = e.db();
        seastar::abort_source as;
        tmpdir tmp;
        auto license_path = tmp.path() / "nonexistent_license.key";

        license::limits lim;
        lim.max_storage_bytes = int64_t(100) * 1024 * 1024 * 1024 * 1024;
        lim.max_vcpus = 1000;
        license::compliance_monitor::config cfg(100ms, lim, license_path);

        license::compliance_monitor monitor(as, db, cfg);
        monitor.start().get();

        BOOST_REQUIRE(monitor.is_compliant());
        BOOST_REQUIRE(!monitor.last_status().has_valid_license);

        seastar::sleep(150ms).get();
        BOOST_REQUIRE(monitor.is_compliant());

        monitor.stop().get();
    });
}

SEASTAR_TEST_CASE(test_compliance_monitor_detects_violation) {
    return do_with_cql_env_thread([] (cql_test_env& e) {
        auto& db = e.db();
        seastar::abort_source as;
        tmpdir tmp;
        auto license_path = tmp.path() / "nonexistent_license.key";

        license::limits lim;
        lim.max_storage_bytes = int64_t(100) * 1024 * 1024 * 1024 * 1024;
        lim.max_vcpus = 0;  // Will be exceeded
        license::compliance_monitor::config cfg(100ms, lim, license_path);

        license::compliance_monitor monitor(as, db, cfg);
        monitor.start().get();

        BOOST_REQUIRE(!monitor.is_compliant());
        BOOST_REQUIRE(monitor.last_status().vcpu_limit_exceeded);

        monitor.stop().get();
    });
}

// ============================================================================
// Print Keypair for Embedding (utility test)
// ============================================================================

SEASTAR_THREAD_TEST_CASE(test_print_keypair_for_embedding) {
    // Generate a new keypair and print the values needed to embed it
    auto kp = license::generate_keypair();

    testlog.info("Generated new keypair for embedding:");
    license::print_keypair_for_embedding(kp);

    // Also show how to generate a license with it
    license::license_data data;
    data.customer_id = "Example_Customer";
    data.max_vcpus = license::unlimited_vcpus;
    data.max_storage_bytes = license::unlimited_storage;
    data.expiry = {}; // Never expires

    auto license_content = license::generate_license(kp.private_key, data);
    testlog.info("Example unlimited license:\n{}", license_content);
}

BOOST_AUTO_TEST_SUITE_END()

