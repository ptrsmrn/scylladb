/*
 * Copyright (C) 2026 ScyllaDB
 */

/*
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

#include "audit/audit_stdout_storage_helper.hh"

#include <memory>
#include <unistd.h>

#include <seastar/core/coroutine.hh>
#include <seastar/core/fstream.hh>
#include <seastar/core/iostream.hh>
#include <seastar/core/smp.hh>

#include <fmt/chrono.h>
#include <fmt/format.h>

#include "cql3/query_processor.hh"

namespace cql3 {

class query_processor;

}

namespace audit {

namespace {

/// Writes audit messages to stdout, serialised on shard 0.
///
/// All audit writes are funnelled to shard 0 via smp::submit_to() and then
/// serialised through a semaphore so that concurrent events from different
/// shards don't interleave on the wire.
///
/// The I/O is performed asynchronously via seastar's chardev output stream
/// (make_chardev_output_stream), which dispatches blocking write(2) calls to
/// the reactor's thread pool.  This avoids stalling the reactor loop on I/O.
///
/// A dup()'d copy of STDOUT_FILENO is used because make_chardev_output_stream
/// takes ownership of the fd and closes it on shutdown — we must not close the
/// process's actual stdout descriptor.
struct shard0_stdout_writer {
    seastar::semaphore semaphore{1};
    seastar::gate gate;
    seastar::output_stream<char> stream;

    shard0_stdout_writer(seastar::output_stream<char> os)
            : stream(std::move(os)) {
    }

    future<> write(sstring msg) {
        return seastar::with_gate(gate, [this, msg = std::move(msg)] () mutable -> future<> {
            auto units = co_await get_units(semaphore, 1);
            msg += "\n";
            co_await stream.write(msg);
            co_await stream.flush();
        });
    }

    future<> stop() {
        co_await gate.close();
        co_await stream.close();
    }
};

thread_local std::unique_ptr<shard0_stdout_writer> local_writer;

/// Collapse newlines so each audit record stays on a single log line.
static sstring flatten_stdout_field(std::string_view value) {
    std::string result;
    result.reserve(value.size());
    for (char c : value) {
        result.push_back((c == '\n' || c == '\r') ? ' ' : c);
    }
    return sstring(result);
}

static sstring make_stdout_audit_message(socket_address node_ip,
                                         std::string_view category,
                                         std::string_view cl,
                                         bool error,
                                         std::string_view keyspace,
                                         std::string_view query,
                                         socket_address client_ip,
                                         std::string_view table,
                                         std::string_view username) {
    const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    tm time;
    localtime_r(&now, &time);

    return seastar::format(
            R"({:%h %e %T} scylla-audit: node="{}", category="{}", cl="{}", error="{}", keyspace="{}", query="{}", client_ip="{}", table="{}", username="{}")",
            time,
            node_ip,
            flatten_stdout_field(category),
            flatten_stdout_field(cl),
            error ? "true" : "false",
            flatten_stdout_field(keyspace),
            flatten_stdout_field(query),
            client_ip,
            flatten_stdout_field(table),
            flatten_stdout_field(username));
}

} // anonymous namespace

future<> audit_stdout_storage_helper::stdout_send_helper(sstring msg) {
    try {
        co_await seastar::smp::submit_to(0, [msg = std::move(msg)] () mutable {
            if (!local_writer) {
                throw std::logic_error("stdout audit backend is not started");
            }
            return local_writer->write(std::move(msg));
        });
    } catch (const std::exception& e) {
        auto error_msg = seastar::format(
            "Stdout audit backend failed (writing a message to stdout resulted in {}).",
            e);
        logger.error("{}", error_msg);
        throw audit_exception(std::move(error_msg));
    }
}

audit_stdout_storage_helper::audit_stdout_storage_helper(cql3::query_processor& /*qp*/, service::migration_manager& /*mm*/) {
}

audit_stdout_storage_helper::~audit_stdout_storage_helper() = default;

future<> audit_stdout_storage_helper::start(const db::config& /*cfg*/) {
    if (this_shard_id() == 0) {
        // dup() STDOUT_FILENO because make_chardev_output_stream takes
        // ownership of the fd and closes it when the stream is shut down.
        // We must not close the process's actual stdout.
        int fd = ::dup(STDOUT_FILENO);
        if (fd == -1) {
            throw std::system_error(errno, std::system_category(), "dup(STDOUT_FILENO) for audit");
        }
        auto os = seastar::make_chardev_output_stream(seastar::file_desc::from_fd(fd));
        local_writer = std::make_unique<shard0_stdout_writer>(std::move(os));
        logger.info("Initializing stdout audit backend.");
    }
    co_return;
}

future<> audit_stdout_storage_helper::stop() {
    if (this_shard_id() == 0 && local_writer) {
        co_await local_writer->stop();
        local_writer.reset();
    }
    co_return;
}

future<> audit_stdout_storage_helper::write(
        const audit_info* ai, socket_address node_ip, socket_address client_ip, db::consistency_level cl, const sstring& username, bool error) {
    co_return co_await stdout_send_helper(make_stdout_audit_message(
            node_ip,
            ai->category_string(),
            fmt::to_string(cl),
            error,
            ai->keyspace(),
            ai->query(),
            client_ip,
            ai->table(),
            username));
}

future<> audit_stdout_storage_helper::write_login(const sstring& username, socket_address node_ip, socket_address client_ip, bool error) {
    co_return co_await stdout_send_helper(make_stdout_audit_message(
            node_ip,
            "AUTH",
            "",
            error,
            "",
            "",
            client_ip,
            "",
            username));
}

} // namespace audit
