# IshikuraDB（石蔵）
> In Japanese: *Stone Storehouse*

A high-performance, ACID-compliant database written in C++ with enterprise-grade security features.

## Features

- **ACID Transactions** - Full transactional support with WAL
- **B+ Tree Storage** - Optimized on-disk data structures
- **TLS Encryption** - Secure client-server communication
- **API Key Management** - Fine-grained access control with rate limiting
- **Audit Logging** - Comprehensive security event tracking
- **Binary Protocol** - Efficient wire format for high performance

## Requirements

- **C++23** compatible compiler (GCC 13+, Clang 16+)
- **CMake 3.23** or later
- **OpenSSL** development libraries

## Quick Start

### Build
```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Run Server
```bash
# Standard server
./src/ishikura_server --port 9090

# TLS server with encryption
./src/ishikura_tls_server --port 9443 --cert server.crt --key server.key
```

### Client Operations
```bash
# Basic client demo
./src/ishikura_client_demo

# TLS client
./src/ishikura_tls_client --host localhost --port 9443
```

### API Key Management
```bash
# Generate API key with permissions
./src/ishikura_api_key_manager generate "my-app" "user123" --permissions "read,write"

# Validate API key
./src/ishikura_api_key_manager validate <api-key> "read"
```

## Testing

```bash
# Run all tests
./tests/tests

# Security tests only
./tests/tests "[security]"

# Comprehensive security testing
./scripts/run_security_tests.sh
```

## Security Features

- **TLS 1.2/1.3** with configurable cipher suites
- **API Keys** with granular permissions and rate limiting
- **Audit Logging** with 45+ event types and async processing
- **Vulnerability Scanning** with automated security checks
- **Memory Safety** testing with Valgrind integration

## Configuration

Server configuration via JSON:
```json
{
  "port": 9090,
  "max_connections": 1000,
  "storage_path": "./data",
  "enable_tls": true,
  "audit_log_enabled": true
}
```

## Documentation

- [Architecture Guide](docs/architecture.md) - Complete system design
- [Security Model](docs/security.md) - Threat analysis and controls
- [API Reference](docs/api.md) - Protocol specification

## Performance

- **Throughput**: 100K+ ops/sec single-threaded
- **Latency**: Sub-millisecond for simple operations
- **Storage**: Efficient B+ tree with logarithmic complexity
- **Concurrent**: Thread-safe operations with minimal contention

## License

MIT License - see [LICENSE.md](LICENSE.md) for details.
