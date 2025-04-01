const std = @import("std");
const net = std.net;
const http = std.http;
const crypto = std.crypto;
const fs = std.fs;
const mem = std.mem;
const os = std.os;
const io = std.io;
const json = std.json;
const heap = std.heap;
const log = std.log;
const time = std.time;

const security = @import("security.zig");
const tls_utils = @import("tls_utils.zig");
const tls_secure = @import("tls_secure_conn.zig");

const server_addr = "127.0.0.1";
const server_port = 7777;
const max_header_size = 8192;
const max_body_size = 1024 * 1024;
const connection_timeout_ns = 30 * time.ns_per_s;
const enable_tls = false; // Disabled for development testing (set to true for production)

const tls_config = tls_secure.TlsSecureConfig{
    .cert_file = "certs/server.crt",
    .key_file = "certs/server.key",
    .ca_file = null, // Set to CA file path for client verification
    .verify_client = false,
    .min_version = .v1_3,
    .cipher_strength = .high,
    .use_ocsp_stapling = true,
    .use_sni = true,
    .session_tickets_enabled = false,
    .use_perfect_forward_secrecy = true,
};

const ServerError = error{
    InvalidRequest,
    RequestTooLarge,
    ConnectionTimeout,
    RateLimitExceeded,
    UnsupportedMethod,
    TlsError,
};

const RateLimitEntry = struct {
    count: u32,
    timestamp: i64,
};

const Body = struct {
    csrf_token: []const u8,
    message: ?[]const u8 = null,
};

pub fn main() !void {
    std.log.info("Starting secure server on port 7777...", .{});
    try security.runSecureServer();
}

fn startServer(server: *net.Server, allocator: mem.Allocator, csrf: *security.CsrfProtection) !void {
    // Rate limiting setup (requests per IP address)
    var rate_limiter = std.StringHashMap(RateLimitEntry).init(allocator);
    defer rate_limiter.deinit();

    const cleanup_interval_ms = 5 * 60 * 1000; // 5 minutes
    var last_cleanup = time.milliTimestamp();

    while (true) {
        var connection = server.accept() catch |err| {
            log.err("Connection to Zwicky interrupted: {}", .{err});
            continue;
        };

        {
            var should_close_connection = true;
            defer {
                if (should_close_connection) {
                    connection.stream.close();
                }
            }

            const client_addr = connection.address;
            const addr_str = std.fmt.allocPrint(allocator, "{}", .{client_addr}) catch |err| {
                log.err("Failed to format client address: {}", .{err});
                continue;
            };
            defer allocator.free(addr_str);

            if (checkRateLimit(&rate_limiter, addr_str)) {
                log.warn("Rate limit exceeded for IP: {s}", .{addr_str});
                continue;
            }

            const secure_headers = security.getSecureHeaders();

            if (enable_tls) {
                var secure_conn = tls_secure.createSecureServer(tls_config, connection.stream, allocator) catch |err| {
                    log.err("TLS handshake failed: {}", .{err});
                    continue;
                };
                defer secure_conn.deinit();

                should_close_connection = false;

                const security_info = secure_conn.getSecurityInfo();
                log.info("TLS connection established: version={s}, cipher={s}", .{
                    @tagName(security_info.version),
                    security_info.cipher,
                });

                const read_buffer = allocator.alloc(u8, max_header_size) catch |err| {
                    log.err("Failed to allocate read buffer: {}", .{err});
                    continue;
                };
                defer allocator.free(read_buffer);

                var http_server = http.Server.init(connection, read_buffer);

                var request = http_server.receiveHead() catch |err| {
                    log.err("Failed to read request head: {s}", .{@errorName(err)});
                    continue;
                };

                const now = time.milliTimestamp();
                if (now - last_cleanup > cleanup_interval_ms) {
                    csrf.cleanupExpiredTokens();
                    last_cleanup = now;
                }

                handleRequest(&request, allocator, addr_str, csrf, secure_headers) catch |err| {
                    log.err("Failed to handle TLS request: {s}", .{@errorName(err)});

                    // Try to send an error response but don't panic if it fails
                    if (err == ServerError.InvalidRequest) {
                        _ = request.respond("400 Bad Request\n", .{}) catch |resp_err| {
                            log.err("Failed to send error response: {s}", .{@errorName(resp_err)});
                        };
                    } else if (err == ServerError.RequestTooLarge) {
                        _ = request.respond("413 Payload Too Large\n", .{}) catch |resp_err| {
                            log.err("Failed to send error response: {s}", .{@errorName(resp_err)});
                        };
                    } else if (err == ServerError.RateLimitExceeded) {
                        _ = request.respond("429 Too Many Requests\n", .{}) catch |resp_err| {
                            log.err("Failed to send error response: {s}", .{@errorName(resp_err)});
                        };
                    } else if (err == ServerError.UnsupportedMethod) {
                        _ = request.respond("405 Method Not Allowed\n", .{}) catch |resp_err| {
                            log.err("Failed to send error response: {s}", .{@errorName(resp_err)});
                        };
                    } else if (err == ServerError.TlsError) {
                        _ = request.respond("400 TLS Error\n", .{}) catch |resp_err| {
                            log.err("Failed to send error response: {s}", .{@errorName(resp_err)});
                        };
                    } else {
                        _ = request.respond("500 Internal Server Error\n", .{}) catch |resp_err| {
                            log.err("Failed to send error response: {s}", .{@errorName(resp_err)});
                        };
                    }
                    continue;
                };
            } else {
                const read_buffer = allocator.alloc(u8, max_header_size) catch |err| {
                    log.err("Failed to allocate read buffer: {}", .{err});
                    continue;
                };
                defer allocator.free(read_buffer);

                var http_server = http.Server.init(connection, read_buffer);

                var request = http_server.receiveHead() catch |err| {
                    log.err("Failed to read request head: {s}", .{@errorName(err)});
                    continue;
                };

                const now = time.milliTimestamp();
                if (now - last_cleanup > cleanup_interval_ms) {
                    csrf.cleanupExpiredTokens();
                    last_cleanup = now;
                }

                handleRequest(&request, allocator, addr_str, csrf, secure_headers) catch |err| {
                    log.err("Failed to handle request: {s}", .{@errorName(err)});

                    // Try to send an error response but don't panic if it fails its fine its fine
                    if (err == ServerError.InvalidRequest) {
                        _ = request.respond("400 Bad Request\n", .{}) catch |resp_err| {
                            log.err("Failed to send error response: {s}", .{@errorName(resp_err)});
                        };
                    } else if (err == ServerError.RequestTooLarge) {
                        _ = request.respond("413 Payload Too Large\n", .{}) catch |resp_err| {
                            log.err("Failed to send error response: {s}", .{@errorName(resp_err)});
                        };
                    } else if (err == ServerError.RateLimitExceeded) {
                        _ = request.respond("429 Too Many Requests\n", .{}) catch |resp_err| {
                            log.err("Failed to send error response: {s}", .{@errorName(resp_err)});
                        };
                    } else if (err == ServerError.UnsupportedMethod) {
                        _ = request.respond("405 Method Not Allowed\n", .{}) catch |resp_err| {
                            log.err("Failed to send error response: {s}", .{@errorName(resp_err)});
                        };
                    } else if (err == ServerError.TlsError) {
                        _ = request.respond("400 TLS Error\n", .{}) catch |resp_err| {
                            log.err("Failed to send error response: {s}", .{@errorName(resp_err)});
                        };
                    } else {
                        _ = request.respond("500 Internal Server Error\n", .{}) catch |resp_err| {
                            log.err("Failed to send error response: {s}", .{@errorName(resp_err)});
                        };
                    }
                    continue;
                };
            }
        }
    }
}

fn checkRateLimit(rate_limiter: *std.StringHashMap(RateLimitEntry), client_addr: []const u8) bool {
    const now = time.milliTimestamp();
    const window_ms = 60 * 1000; // 1 minute window
    const max_requests = 100; // Maximum 100 requests per minute

    if (rate_limiter.get(client_addr)) |entry| {
        // Check if window has passed
        if (now - entry.timestamp > window_ms) {
            // Reset the entry if the time window has passed
            rate_limiter.put(client_addr, .{ .count = 1, .timestamp = now }) catch return true;
            return false;
        }

        const new_count = entry.count + 1;
        rate_limiter.put(client_addr, .{ .count = new_count, .timestamp = entry.timestamp }) catch return true;

        return new_count > max_requests;
    } else {
        const key_copy = rate_limiter.allocator.dupe(u8, client_addr) catch return true;

        rate_limiter.put(key_copy, .{ .count = 1, .timestamp = now }) catch {
            // Free the key if we failed to insert
            rate_limiter.allocator.free(key_copy);
            return true;
        };

        return false;
    }
}

fn handleRequest(request: *http.Server.Request, allocator: mem.Allocator, client_addr: []const u8, csrf: *security.CsrfProtection, secure_headers: [7]http.Header) !void {
    log.info("Request from {s}: {s} {s}", .{ client_addr, @tagName(request.head.method), request.head.target });

    if (request.head.method != .GET and
        request.head.method != .POST and
        request.head.method != .HEAD)
    {
        return ServerError.UnsupportedMethod;
    }

    if (request.head.target.len == 0 or request.head.target.len > 1024) {
        return ServerError.InvalidRequest;
    }

    if (!security.validateRequestParams(request.head.target)) {
        log.warn("Potential malicious request from {s}: {s}", .{ client_addr, request.head.target });
        return ServerError.InvalidRequest;
    }

    if (mem.eql(u8, request.head.target, "/") or mem.eql(u8, request.head.target, "/index.html")) {
        try handleHome(request, csrf, allocator, secure_headers);
    } else if (mem.startsWith(u8, request.head.target, "/api/")) {
        try handleApi(request, allocator, csrf, secure_headers);
    } else if (mem.eql(u8, request.head.target, "/health")) {
        try request.respond("OK", .{
            .extra_headers = &secure_headers,
            .status = .ok,
        });
    } else {
        var headers_buffer: [8]http.Header = undefined;
        var headers_count = secure_headers.len;
        @memcpy(headers_buffer[0..headers_count], secure_headers[0..]);
        headers_buffer[headers_count] = .{ .name = "Content-Type", .value = "text/plain" };
        headers_count += 1;

        try request.respond("404 Not Found\n", .{
            .extra_headers = headers_buffer[0..headers_count],
            .status = .not_found,
        });
    }
}

fn handleHome(request: *http.Server.Request, csrf: *security.CsrfProtection, allocator: mem.Allocator, secure_headers: [7]http.Header) !void {
    const csrf_token = try csrf.generateToken();
    defer allocator.free(csrf_token);

    const home_page = try std.fmt.allocPrint(allocator,
        \\<!DOCTYPE html>
        \\<html>
        \\<head>
        \\    <title>Zwicky HTTPS Server</title>
        \\    <meta charset="UTF-8">
        \\    <meta name="viewport" content="width=device-width, initial-scale=1.0">
        \\</head>
        \\<body>
        \\    <h1>Welcome to Zwicky HTTPS Server</h1>
        \\    <p>This server implements several security features:</p>
        \\    <ul>
        \\        <li>Input validation</li>
        \\        <li>Rate limiting</li>
        \\        <li>Security headers</li>
        \\        <li>Request timeouts</li>
        \\        <li>TLS support (when enabled)</li>
        \\        <li>CSRF protection</li>
        \\    </ul>
        \\    <form action="/api/submit" method="post">
        \\        <input type="hidden" name="csrf_token" value="{s}">
        \\        <label for="message">Message:</label>
        \\        <input type="text" id="message" name="message">
        \\        <button type="submit">Submit</button>
        \\    </form>
        \\</body>
        \\</html>
    , .{csrf_token});
    defer allocator.free(home_page);

    var headers_buffer: [8]http.Header = undefined;
    var headers_count = secure_headers.len;
    @memcpy(headers_buffer[0..headers_count], secure_headers[0..]);
    headers_buffer[headers_count] = .{ .name = "Content-Type", .value = "text/html; charset=UTF-8" };
    headers_count += 1;

    try request.respond(home_page, .{
        .extra_headers = headers_buffer[0..headers_count],
    });
}

fn handleApi(request: *http.Server.Request, allocator: mem.Allocator, csrf: *security.CsrfProtection, secure_headers: [7]http.Header) !void {
    const csrf_token = try csrf.generateToken();
    defer allocator.free(csrf_token);

    var headers_buffer: [8]http.Header = undefined;
    var headers_count = secure_headers.len;
    @memcpy(headers_buffer[0..headers_count], secure_headers[0..]);
    headers_buffer[headers_count] = .{ .name = "Content-Type", .value = "application/json" };
    headers_count += 1;

    if (request.head.method == .POST) {
        const is_valid_csrf = csrf.validateToken(csrf_token);

        if (!is_valid_csrf) {
            const error_response =
                \\{
                \\  "status": "error",
                \\  "message": "Invalid or missing CSRF token"
                \\}
            ;
            try request.respond(error_response, .{
                .extra_headers = headers_buffer[0..headers_count],
                .status = .bad_request,
            });
            return;
        }
    }

    var request_id_buf: [16]u8 = undefined;
    crypto.random.bytes(&request_id_buf);
    var request_id: [32]u8 = undefined;
    _ = std.fmt.bufPrint(&request_id, "{x}", .{std.fmt.fmtSliceHexLower(&request_id_buf)}) catch "";

    const api_response = try std.fmt.allocPrint(allocator,
        \\{{
        \\  "status": "success",
        \\  "message": "API endpoint reached",
        \\  "server_time": {d},
        \\  "endpoint": "{s}",
        \\  "request_id": "{s}"
        \\}}
    , .{
        time.milliTimestamp(),
        request.head.target,
        request_id,
    });
    defer allocator.free(api_response);

    try request.respond(api_response, .{
        .extra_headers = headers_buffer[0..headers_count],
    });
}
