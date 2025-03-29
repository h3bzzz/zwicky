const std = @import("std");
const fs = std.fs;
const os = std.os;
const crypto = std.crypto;
const heap = std.heap;
const log = std.log;
const time = std.time;

// This is a simple tool to generate self-signed certificates for testing purposes
// In a production environment, you should use certificates from a trusted CA

pub fn main() !void {
    log.info("Generating self-signed certificates for TLS testing...", .{});

    // Set up allocator
    var gpa = heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    // Create certificates directory if it doesn't exist
    try fs.cwd().makePath("certs");

    // Generate certificates using external OpenSSL
    const results = try generateWithOpenSSL();

    if (results) {
        log.info("Successfully generated certificates in the 'certs' directory", .{});
        log.info("To use these certificates, set enable_tls = true in src/main.zig", .{});
    } else {
        log.err("Failed to generate certificates. Please install OpenSSL and try again.", .{});
    }
}

// Define the key type to use
const KeyType = enum {
    rsa,
    ec,
};

fn generateWithOpenSSL() !bool {
    const key_type = KeyType.rsa; // Change to .ec for elliptic curve

    // Check for O
    const openssl_check = std.ChildProcess.exec(.{
        .allocator = heap.page_allocator,
        .argv = &[_][]const u8{ "openssl", "version" },
    }) catch |err| {
        log.err("Failed to run OpenSSL: {}", .{err});
        return false;
    };
    defer {
        heap.page_allocator.free(openssl_check.stdout);
        heap.page_allocator.free(openssl_check.stderr);
    }

    if (openssl_check.term.Exited != 0) {
        log.err("OpenSSL not found. Please install OpenSSL first.", .{});
        return false;
    }

    log.info("OpenSSL found: {s}", .{std.mem.trim(u8, openssl_check.stdout, "\n\r")});

    // Generate private key
    log.info("Generating private key ({s})...", .{@tagName(key_type)});

    const key_result = if (key_type == .rsa) blk: {
        // Generate RSA key
        break :blk std.ChildProcess.exec(.{
            .allocator = heap.page_allocator,
            .argv = &[_][]const u8{
                "openssl", "genrsa",
                "-out",    "certs/server.key",
                "4096",
            },
        }) catch |err| {
            log.err("Failed to generate RSA private key: {}", .{err});
            return false;
        };
    } else blk: {
        // Generate EC key (using P-384 curve for strong security)
        break :blk std.ChildProcess.exec(.{
            .allocator = heap.page_allocator,
            .argv = &[_][]const u8{ "openssl", "ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", "certs/server.key" },
        }) catch |err| {
            log.err("Failed to generate EC private key: {}", .{err});
            return false;
        };
    };
    defer {
        heap.page_allocator.free(key_result.stdout);
        heap.page_allocator.free(key_result.stderr);
    }

    if (key_result.term.Exited != 0) {
        log.err("Failed to generate private key: {s}", .{key_result.stderr});
        return false;
    }

    // Generate CSR (Certificate Signing Request)
    log.info("Generating certificate signing request...", .{});

    // Create a config file for the CSR
    const config_content =
        \\[req]
        \\distinguished_name = req_distinguished_name
        \\req_extensions = v3_req
        \\prompt = no
        \\
        \\[req_distinguished_name]
        \\C = US
        \\ST = State
        \\L = City
        \\O = Zig Secure Server
        \\OU = Development
        \\CN = localhost
        \\
        \\[v3_req]
        \\keyUsage = keyEncipherment, dataEncipherment
        \\extendedKeyUsage = serverAuth
        \\subjectAltName = @alt_names
        \\
        \\[alt_names]
        \\DNS.1 = localhost
        \\IP.1 = 127.0.0.1
    ;

    const config_file = try fs.cwd().createFile("certs/openssl.cnf", .{});
    defer config_file.close();
    try config_file.writeAll(config_content);

    // Generate CSR with the config
    const csr_result = std.ChildProcess.exec(.{
        .allocator = heap.page_allocator,
        .argv = &[_][]const u8{ "openssl", "req", "-new", "-key", "certs/server.key", "-out", "certs/server.csr", "-config", "certs/openssl.cnf" },
    }) catch |err| {
        log.err("Failed to generate CSR: {}", .{err});
        return false;
    };
    defer {
        heap.page_allocator.free(csr_result.stdout);
        heap.page_allocator.free(csr_result.stderr);
    }

    if (csr_result.term.Exited != 0) {
        log.err("Failed to generate CSR: {s}", .{csr_result.stderr});
        return false;
    }

    // Generate self-signed certificate
    log.info("Generating self-signed certificate...", .{});
    const cert_result = std.ChildProcess.exec(.{
        .allocator = heap.page_allocator,
        .argv = &[_][]const u8{
            "openssl",           "x509",
            "-req",              "-days",
            "365",               "-in",
            "certs/server.csr",  "-signkey",
            "certs/server.key",  "-out",
            "certs/server.crt",  "-extensions",
            "v3_req",            "-extfile",
            "certs/openssl.cnf", "-sha256",
        },
    }) catch |err| {
        log.err("Failed to generate certificate: {}", .{err});
        return false;
    };
    defer {
        heap.page_allocator.free(cert_result.stdout);
        heap.page_allocator.free(cert_result.stderr);
    }

    if (cert_result.term.Exited != 0) {
        log.err("Failed to generate certificate: {s}", .{cert_result.stderr});
        return false;
    }

    // Display certificate info
    log.info("Certificate information:", .{});
    const info_result = std.ChildProcess.exec(.{
        .allocator = heap.page_allocator,
        .argv = &[_][]const u8{ "openssl", "x509", "-in", "certs/server.crt", "-text", "-noout" },
    }) catch |err| {
        log.err("Failed to display certificate info: {}", .{err});
        return false;
    };
    defer {
        heap.page_allocator.free(info_result.stdout);
        heap.page_allocator.free(info_result.stderr);
    }

    if (info_result.term.Exited != 0) {
        log.err("Failed to display certificate info: {s}", .{info_result.stderr});
        return false;
    }

    fs.cwd().deleteFile("certs/server.csr") catch |err| {
        log.warn("Failed to delete CSR file: {}", .{err});
    };

    fs.cwd().deleteFile("certs/openssl.cnf") catch |err| {
        log.warn("Failed to delete config file: {}", .{err});
    };

    return true;
}
