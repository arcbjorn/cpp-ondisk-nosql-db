---
title: Home
---

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

## Documentation

- [API Reference](api) - Protocol specification and operations
- [Architecture Guide](architecture) - Complete system design
- [Security Model](security) - Threat analysis and controls

## Performance

- **Throughput**: 100K+ ops/sec single-threaded
- **Latency**: Sub-millisecond for simple operations
- **Storage**: Efficient B+ tree with logarithmic complexity
- **Concurrent**: Thread-safe operations with minimal contention

## Requirements

- **C++23** compatible compiler (GCC 13+, Clang 16+)
- **CMake 3.23** or later
- **OpenSSL** development libraries