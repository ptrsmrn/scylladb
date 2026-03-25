/*
 * Copyright (C) 2026 ScyllaDB
 */

/*
 * SPDX-License-Identifier: LicenseRef-ScyllaDB-Source-Available-1.0
 */

#include "audit/audit_stdout_storage_helper.hh"

#include <cerrno>
#include <system_error>
#include <unistd.h>

#include <seastar/core/coroutine.hh>

#include <fmt/chrono.h>
#include <fmt/format.h>

#include "cql3/query_processor.hh"

namespace cql3 {

class query_processor;

}

namespace audit {

namespace {

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

// ---- stdout_send_helper: per-shard serialized write ----
//
// Mirrors syslog_send_helper():
//   1. Acquire the per-shard semaphore (serialize writes within a shard).
//   2. Write the message + newline to _fd via POSIX write(2).
//
// Why not use Seastar async I/O primitives?
//
//   - io_queue::submit_io_write():  The Seastar I/O scheduler dispatches
//     writes through the reactor backend.  On the linux-aio backend
//     (IOCB_CMD_PWRITE via io_submit) this fails with EOPNOTSUPP for
//     non-filesystem fds such as pipes or dup'd stdout.  On io_uring the
//     call would work (IORING_OP_WRITE handles any fd), but we cannot
//     require io_uring — linux-aio is the default on many production
//     kernels.
//
//   - pollable_fd::write_all():  The pollable_fd write path ultimately
//     calls sendmsg() with MSG_NOSIGNAL (see reactor::do_sendmsg and the
//     io_uring backend's sendmsg codepath).  sendmsg() returns ENOTSOCK
//     on non-socket fds (pipes, regular files), so this is unusable.
//     Additionally, regular files cannot be registered with epoll
//     (EPERM), which breaks the pollable_fd readiness model.
//
// The synchronous write(2) approach is the same one Seastar's own logger
// uses for stderr/stdout output (see seastar/src/util/log.cc).  Audit
// messages are well under PIPE_BUF (4096 on Linux), so the kernel
// handles them as a single atomic buffer copy — the stdout analogue of
// syslog's datagram atomicity.  The syslog audit backend similarly
// relies on a synchronous datagram_channel::send() that performs a
// sendmsg() syscall directly on the reactor thread.
future<> audit_stdout_storage_helper::stdout_send_helper(sstring msg) {
    try {
        auto lock = co_await get_units(_semaphore, 1, std::chrono::hours(1));

        msg += "\n";
        const char* ptr = msg.data();
        size_t remaining = msg.size();
        while (remaining) {
            auto written = ::write(_fd, ptr, remaining);
            if (written == -1) {
                if (errno == EINTR) {
                    continue;
                }
                throw std::system_error(errno, std::system_category(), "stdout audit write");
            }
            ptr += written;
            remaining -= written;
        }
    } catch (const std::exception& e) {
        auto error_msg = seastar::format(
            "Stdout audit backend failed (writing a message to stdout resulted in {}).",
            e);
        logger.error("{}", error_msg);
        throw audit_exception(std::move(error_msg));
    }
}

audit_stdout_storage_helper::audit_stdout_storage_helper(cql3::query_processor& /*qp*/, service::migration_manager& /*mm*/)
    : _fd(::dup(STDOUT_FILENO))
    , _semaphore(1) {
    if (_fd == -1) {
        throw std::system_error(errno, std::system_category(), "dup(STDOUT_FILENO)");
    }
}

audit_stdout_storage_helper::~audit_stdout_storage_helper() {
    if (_fd != -1) {
        ::close(_fd);
    }
}

future<> audit_stdout_storage_helper::start(const db::config& /*cfg*/) {
    if (this_shard_id() == 0) {
        logger.info("Initializing stdout audit backend.");
    }
    co_return;
}

future<> audit_stdout_storage_helper::stop() {
    if (_fd != -1) {
        ::close(_fd);
        _fd = -1;
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
