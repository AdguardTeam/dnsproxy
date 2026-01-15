# Quick Start Guide - Batch DoH Queries

## Installation & Build

```bash
cd /home/kexi/dnsproxy
go build -v ./...
```

## Quick Start Commands

### 1. Start dnsproxy with batch support

```bash
./dnsproxy \
  --http-port=8080 \
  --http-batch-path=/dns-batch \
  --http-batch-jwt-secret=mySecret123 \
  --upstream=8.8.8.8
```

### 2. Generate JWT Token (Python)

```bash
pip3 install pyjwt

python3 -c "
import jwt
import uuid
from datetime import datetime, timezone

secret = 'mySecret123'
payload = {
    'timestamp': datetime.now(timezone.utc).isoformat(),
    'id': str(uuid.uuid4())
}
print(jwt.encode(payload, secret, algorithm='HS256'))
"
```

### 3. Send Batch Query

```bash
TOKEN="your-jwt-token-here"

curl -X POST http://localhost:8080/dns-batch \
  -H "Content-Type: application/json" \
  -d '{
    "token": "'$TOKEN'",
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "id": "'$(uuidgen)'",
    "query": [
        {
            "type": ["A", "AAAA"],
            "domain": ["google.com", "cloudflare.com"]
        }
    ]
}' | jq .
```

### 4. Use Test Script

```bash
chmod +x test_batch_doh.sh
./test_batch_doh.sh
```

## Configuration Options

| Option | Description | Example |
|--------|-------------|---------|
| `--http-port` | HTTP (non-SSL) listen port | `--http-port=8080` |
| `--http-path` | Standard DoH query path | `--http-path=/dns-query` |
| `--http-batch-path` | Batch query path | `--http-batch-path=/dns-batch` |
| `--http-batch-jwt-secret` | JWT signing secret | `--http-batch-jwt-secret=secret123` |

## Request Format

```json
{
    "token": "JWT_TOKEN",
    "timestamp": "2026-01-15T10:00:00Z",
    "id": "uuid",
    "query": [
        {
            "type": ["A", "AAAA", "MX"],
            "domain": ["example.com", "google.com"]
        }
    ]
}
```

## Response Format

```json
[
    {
        "domain": "example.com",
        "type": "A",
        "status": "success",
        "answers": ["93.184.216.34"],
        "ttl": 300,
        "rcode": "NOERROR",
        "query_time_ms": 23.456,
        "timestamp": "2026-01-15T10:00:00Z"
    }
]
```

## Supported Query Types

A, AAAA, CNAME, MX, TXT, NS, PTR, SOA, SRV

## Troubleshooting

| Issue | Solution |
|-------|----------|
| 401 Unauthorized | Check JWT secret matches |
| 405 Method Not Allowed | Use POST for batch queries |
| 400 Bad Request | Verify JSON format |
| Connection refused | Check dnsproxy is running |

## Full Documentation

- `BATCH_DOH_EXAMPLE.md` - Detailed usage guide
- `IMPLEMENTATION_SUMMARY.md` - Technical implementation details
- `test_batch_doh.sh` - Automated test script
