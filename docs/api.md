# IshikuraDB API Reference

## Binary Protocol

IshikuraDB uses an efficient binary protocol for client-server communication.

### Message Format

```
[Header: 8 bytes] [Payload: Variable]
```

**Header Structure:**
- `message_type` (4 bytes): Operation type
- `payload_size` (4 bytes): Size of payload data

### Operations

#### PUT
Store a key-value pair.

**Request:**
```
message_type: 0x0001
payload: [key_size][key][value_size][value]
```

**Response:**
```
message_type: 0x0002
payload: [status_code]
```

#### GET
Retrieve value for a key.

**Request:**
```
message_type: 0x0003
payload: [key_size][key]
```

**Response:**
```
message_type: 0x0004
payload: [status_code][value_size][value]
```

#### DELETE
Remove a key-value pair.

**Request:**
```
message_type: 0x0005
payload: [key_size][key]
```

**Response:**
```
message_type: 0x0006
payload: [status_code]
```

#### QUERY
Execute query operations (SCAN, PREFIX, RANGE, COUNT).

**Request:**
```
message_type: 0x0020
payload: [query_size][query_string]
```

**Response:**
```
message_type: 0x0021
payload: [status_code][result_count][results...]
```

**Query Formats:**
- `SCAN` - List all keys
- `PREFIX <prefix>` - Keys starting with prefix
- `RANGE <start>|<end>` - Keys in range (inclusive)
- `COUNT` - Total key count

#### BATCH
Execute multiple operations atomically.

**Request:**
```
message_type: 0x0010
payload: [item_count][items...]
```

**Batch Item:**
```
[operation][key_size][key][value_size][value]
```

**Response:**
```
message_type: 0x0011
payload: [status_code][result_count][results...]
```

#### PING
Health check operation.

**Request:**
```
message_type: 0x0100
payload: []
```

**Response:**
```
message_type: 0x0101
payload: [status_code]
```

### Status Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | SUCCESS | Operation completed successfully |
| 1 | KEY_NOT_FOUND | Key does not exist |
| 2 | INVALID_REQUEST | Malformed request |
| 3 | INTERNAL_ERROR | Server error |
| 4 | RATE_LIMITED | Too many requests |
| 5 | UNAUTHORIZED | Authentication failed |
| 6 | FORBIDDEN | Permission denied |

## REST API

HTTP interface available via API server.

### Endpoints

#### GET /api/v1/kv/{key}
Retrieve a value.

**Response:**
```json
{
  "key": "example",
  "value": "data",
  "timestamp": "2025-01-01T00:00:00Z"
}
```

#### PUT /api/v1/kv/{key}
Store a value.

**Request Body:**
```json
{
  "value": "data"
}
```

#### DELETE /api/v1/kv/{key}
Remove a key.

**Response:** 204 No Content

#### POST /api/v1/query
Execute query operations.

**Request Body:**
```json
{
  "query": "PREFIX user:",
  "limit": 100
}
```

**Response:**
```json
{
  "results": [
    {"key": "user:1", "value": "alice"},
    {"key": "user:2", "value": "bob"}
  ],
  "count": 2
}
```

#### POST /api/v1/batch
Execute batch operations.

**Request Body:**
```json
{
  "operations": [
    {"operation": "PUT", "key": "key1", "value": "value1"},
    {"operation": "GET", "key": "key2"},
    {"operation": "DELETE", "key": "key3"}
  ]
}
```

## Authentication

### API Keys

All requests require a valid API key in the header:

```
Authorization: Bearer <api-key>
```

### Permissions

- `READ` - GET, QUERY operations
- `WRITE` - PUT operations  
- `DELETE` - DELETE operations
- `QUERY` - Advanced query operations
- `BATCH_OPS` - Batch operations
- `ADMIN_*` - Administrative functions

### Rate Limiting

- Default: 1000 requests/minute per API key
- Headers returned: `X-RateLimit-Limit`, `X-RateLimit-Remaining`

## TLS Configuration

### Server Setup

```bash
./ishikura_tls_server \
  --port 9443 \
  --cert server.crt \
  --key server.key \
  --min-tls-version 1.2
```

### Client Connection

```bash
./ishikura_tls_client \
  --host localhost \
  --port 9443 \
  --verify-cert
```

### Cipher Suites

Supported secure cipher suites:
- `TLS_AES_256_GCM_SHA384` (TLS 1.3)
- `TLS_AES_128_GCM_SHA256` (TLS 1.3)  
- `ECDHE-RSA-AES256-GCM-SHA384` (TLS 1.2)
- `ECDHE-RSA-AES128-GCM-SHA256` (TLS 1.2)

## Error Handling

### Binary Protocol Errors

Connection closed on protocol violations or authentication failures.

### HTTP API Errors

Standard HTTP status codes with JSON error responses:

```json
{
  "error": {
    "code": "KEY_NOT_FOUND",
    "message": "The requested key does not exist",
    "details": "Key 'example' not found in storage"
  }
}
```

## Client Libraries

### C++ Client

```cpp
#include "network/binary_client.hpp"

BinaryClient client("localhost", 9090);
client.connect();

auto result = client.get("mykey");
if (result.has_value()) {
    std::cout << "Value: " << result.value() << std::endl;
}
```

### Connection Management

- Automatic reconnection on connection loss
- Connection pooling for multiple concurrent requests  
- Configurable timeouts and retry policies