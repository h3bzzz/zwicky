# Zwicky HTTPS Server

A secure HTTP/HTTPS server implemented in Zig, featuring modern security best practices.

## Security Features

- 🔒 **TLS Support** - HTTPS with TLS 1.3 support (configurable)
- 🛡️ **Input Validation** - Strong parameter validation to prevent common attacks
- 🧩 **Rate Limiting** - Protection against brute-force and DDoS attacks
- 📝 **Zecurity Headers** - Comprehensive set of modern security headers
- ⏱️ **Connection Timeouts** - Protection against Zlow-loris and resource exhaustion attacks
- 🔑 **CSRF Protection** - HMAC-SHA256 based CSRF tokens with proper validation
- 🔍 **Request Logging and Tracing** - Detailed logging with unique request IDs

## Technologies

- **Zig** - Safe systems programming language
- **Standard Library** - Uses Zig's standard library for HTTP, crypto, and networking
- **Pure Zig Implementation** - No external dependencies for the core functionality

## Getting Started

### Prerequisites

- Zig 0.11.0 or later
- OpenSSL (for certificate generation)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/sec_server.git
   cd sec_server
   ```

2. Generate self-signed certificates for development (not required if TLS is disabled):
   ```bash
   mkdir -p certs
   openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes -subj "/CN=localhost"
   ```

3. Build the project:
   ```bash
   zig build
   ```

4. Run the zerver:
   ```bash
   zig-out/bin/sec_server
   ```

5. Open your browser and navigate to:
   - HTTP: `http://127.0.0.1:7777`
   - HTTPS (if TLS enabled): `https://127.0.0.1:7777` (you'll need to accept the self-signed certificate warning)

### Configuration

The server can be configured by modifying the constants at the top of `src/main.zig`:

```zig
const server_addr = "127.0.0.1";         // Server binding address
const server_port = 7777;                // Server port
const max_header_size = 8192;            // 8KB max header size
const max_body_size = 1024 * 1024;       // 1MB max body size
const connection_timeout_ns = 30 * time.ns_per_s; // 30 seconds timeout
const enable_tls = false;                // Enable/disable TLS
```

## Production Deployment

For production use, consider the following:

1. Use a proper TLS implementation (like mbedTLS or BearSSL)
2. Obtain valid TLS certificates from a trusted CA (Let's Encrypt is free)
3. Enable TLS by setting `enable_tls = true` in the code
4. Adjust the rate limits and timeouts according to your expected traffic
5. Consider running behind a reverse proxy like Nginx or Caddy

## Why Zig for Secure Backends

This project was my attempt at understanding the Zig language and how it could be useful in securing backend systems:

- **Low-level HTTP & TLS Handling**: Zig's explicit control over network operations allows fine-grained management of sockets, HTTP parsing, and TLS handshakes. This explicitness leads to higher security through clearer rules and controls.

- **Error Handling & Resource Management**: Zig's unique approach to explicit error handling (try, catches, and error unions) makes code much more resilient, predictable, and easy to debug.

- **Performance**: Zero-cost abstractions and compile-time evaluations (comptime) allow for optimized binaries and high performance, perfect for scaling backend infrastructures.

- **Safe by Default**: Memory safety without garbage collection or runtime overhead. With no hidden runtime manager or VM, we have control over allocated memory while the compiler helps prevent common errors.

Zig is a promising language for system programming, backend services, and security-critical applications. Its clarity, safety, and speed give you the next level up from C and Go.

## Development and Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Zig language and community
- Security best practices from OWASP

[-= h3bzzz =-]
   ɧ∆çĸ ẗђε ₩øɍℓđ  
  ɧ∆ρρұ ɧ∆çĸɪɳʛ!
