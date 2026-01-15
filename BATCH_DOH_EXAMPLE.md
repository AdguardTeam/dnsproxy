# Custom Batch DoH Query Feature

This document describes the custom batch DNS-over-HTTP (DoH) query feature added to dnsproxy.

## Features

1. **Non-SSL HTTP DoH Server**: Run DoH server on plain HTTP (without TLS) for local/testing use
2. **Configurable Paths**: Set custom paths for standard and batch DoH queries
3. **Batch Query Support**: Query multiple domains/types in a single HTTP request
4. **JWT Authentication**: Secure batch queries with HS256 (HMAC-SHA256) JWT tokens

## Configuration Options

### Command-Line Options

```bash
# HTTP (non-SSL) listener
--http-port=8080                        # Port for HTTP DoH server

# Path configuration
--http-path=/dns-query                  # Path for standard DoH queries
--http-batch-path=/dns-batch           # Path for batch queries

# JWT authentication
--http-batch-jwt-secret=your-secret-key # Shared secret for JWT validation
```

### YAML Configuration

```yaml
http-port:
  - 8080

http-path: /dns-query
http-batch-path: /dns-batch
http-batch-jwt-secret: your-secret-key
```

## Usage Examples

### 1. Start dnsproxy with HTTP and batch support

```bash
./dnsproxy \
  --http-port=8080 \
  --http-batch-path=/dns-batch \
  --http-batch-jwt-secret=mySecretKey123 \
  --upstream=8.8.8.8
```

### 2. Standard DoH Query (GET or POST)

**GET Request:**
```bash
curl "http://localhost:8080/dns-query?dns=$(echo -n "..." | base64 -w0 | tr '+/' '-_' | tr -d '=')"
```

**POST Request:**
```bash
curl -X POST http://localhost:8080/dns-query \
  -H "Content-Type: application/dns-message" \
  --data-binary @query.bin
```

### 3. Batch DoH Query

#### Request Format

```json
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0aW1lc3RhbXAiOiIxNzM3MDAwMDAwIiwiaWQiOiJ1dWlkLWhlcmUifQ.signature",
    "timestamp": "2026-01-15T10:00:00Z",
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "query": [
        {
            "type": ["A", "AAAA"],
            "domain": ["google.com", "cloudflare.com"]
        },
        {
            "type": ["MX"],
            "domain": ["gmail.com"]
        }
    ]
}
```

This will resolve:
- A and AAAA records for google.com
- A and AAAA records for cloudflare.com
- MX records for gmail.com

#### Response Format

```json
[
    {
        "domain": "google.com",
        "type": "A",
        "status": "success",
        "answers": ["142.250.185.46"],
        "ttl": 300,
        "rcode": "NOERROR",
        "query_time_ms": 23.456,
        "timestamp": "2026-01-15T10:00:00.123Z"
    },
    {
        "domain": "google.com",
        "type": "AAAA",
        "status": "success",
        "answers": ["2607:f8b0:4004:c07::64"],
        "ttl": 300,
        "rcode": "NOERROR",
        "query_time_ms": 24.789,
        "timestamp": "2026-01-15T10:00:00.456Z"
    },
    {
        "domain": "cloudflare.com",
        "type": "A",
        "status": "success",
        "answers": ["104.16.132.229", "104.16.133.229"],
        "ttl": 300,
        "rcode": "NOERROR",
        "query_time_ms": 18.234,
        "timestamp": "2026-01-15T10:00:00.789Z"
    }
]
```

### 4. Generate JWT Token

#### Python Example

```python
import jwt
import uuid
from datetime import datetime, timezone

# Configuration
secret = "mySecretKey123"
timestamp = datetime.now(timezone.utc).isoformat()
request_id = str(uuid.uuid4())

# Create payload
payload = {
    "timestamp": timestamp,
    "id": request_id
}

# Generate token
token = jwt.encode(payload, secret, algorithm="HS256")
print(f"Token: {token}")
```

#### Node.js Example

```javascript
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const secret = 'mySecretKey123';
const timestamp = new Date().toISOString();
const requestId = uuidv4();

const payload = {
    timestamp: timestamp,
    id: requestId
};

const token = jwt.sign(payload, secret, { algorithm: 'HS256' });
console.log('Token:', token);
```

### 5. Complete Batch Query Example

```bash
# Generate JWT token (using Python)
TOKEN=$(python3 << EOF
import jwt
import uuid
from datetime import datetime, timezone

secret = "mySecretKey123"
timestamp = datetime.now(timezone.utc).isoformat()
request_id = str(uuid.uuid4())

payload = {
    "timestamp": timestamp,
    "id": request_id
}

token = jwt.encode(payload, secret, algorithm="HS256")
print(token)
EOF
)

# Make batch query request
curl -X POST http://localhost:8080/dns-batch \
  -H "Content-Type: application/json" \
  -d "{
    \"token\": \"$TOKEN\",
    \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
    \"id\": \"$(uuidgen)\",
    \"query\": [
        {
            \"type\": [\"A\", \"AAAA\"],
            \"domain\": [\"google.com\", \"github.com\"]
        }
    ]
}" | jq .
```

## Supported Query Types

- A (IPv4 address)
- AAAA (IPv6 address)
- CNAME (Canonical name)
- MX (Mail exchange)
- TXT (Text records)
- NS (Name server)
- PTR (Pointer record)
- SOA (Start of authority)
- SRV (Service record)

## Security Considerations

1. **HTTP vs HTTPS**:
   - Use HTTP only for local testing or internal networks
   - For production, use HTTPS with TLS certificates (existing `--https-port` and `--tls-*` options)

2. **JWT Secret**:
   - Use a strong, random secret key
   - Keep the secret secure and never commit it to version control
   - Rotate secrets periodically

3. **Token Validation**:
   - The JWT token is validated using HS256 (HMAC-SHA256)
   - Include timestamp and unique ID in the JWT payload for request tracking

## Path Configuration

### Default Behavior (no paths specified)
- All paths accept standard DoH queries
- Batch queries are disabled

### With http-path specified
- Only the specified path accepts standard DoH queries
- Other paths return 404

### With http-batch-path specified
- The batch path accepts batch queries
- Requires http-batch-jwt-secret to be set

### Both paths specified
- Standard queries: handled by http-path
- Batch queries: handled by http-batch-path
- Other paths: return 404

## Example Configuration Files

### config.yaml - HTTP Only (Testing)
```yaml
listen-addrs:
  - 127.0.0.1

http-port:
  - 8080

http-path: /dns-query
http-batch-path: /dns-batch
http-batch-jwt-secret: mySecretKey123

upstream:
  - 8.8.8.8
  - 1.1.1.1

cache: true
cache-size: 65536
```

### config.yaml - HTTPS + HTTP (Production + Local)
```yaml
listen-addrs:
  - 0.0.0.0

# HTTPS with TLS
https-port:
  - 443

tls-crt: /path/to/cert.pem
tls-key: /path/to/key.pem

# HTTP for local use
http-port:
  - 8080

http-path: /dns-query
http-batch-path: /dns-batch
http-batch-jwt-secret: use-strong-secret-here

upstream:
  - 8.8.8.8
  - 1.1.1.1

cache: true
refuse-any: true
```

## Troubleshooting

### Batch queries return 405 Method Not Allowed
- Batch queries only accept POST requests
- Use `-X POST` with curl

### Batch queries return 401 Unauthorized
- JWT token is invalid or expired
- Check that http-batch-jwt-secret matches the secret used to sign the token
- Verify the token signature

### Batch queries return 400 Bad Request
- JSON format is invalid
- Check the request structure matches the expected format
- Ensure Content-Type header is "application/json"

### Standard queries work but batch doesn't
- Verify http-batch-path is configured
- Check that http-batch-jwt-secret is set
- Ensure you're using the correct path in your request
