#!/bin/bash
# Test script for batch DoH queries

set -e

# Configuration
HOST="localhost"
HTTP_PORT="8080"
BATCH_PATH="/dns-batch"
JWT_SECRET="myTestSecret123"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Batch DoH Query Test Script ===${NC}\n"

# Check if dnsproxy is running
if ! curl -s "http://${HOST}:${HTTP_PORT}" > /dev/null 2>&1; then
    echo -e "${RED}Error: dnsproxy is not running on http://${HOST}:${HTTP_PORT}${NC}"
    echo "Start dnsproxy with:"
    echo "  ./dnsproxy --http-port=${HTTP_PORT} --http-batch-path=${BATCH_PATH} --http-batch-jwt-secret=${JWT_SECRET} --upstream=8.8.8.8"
    exit 1
fi

echo -e "${GREEN}✓ dnsproxy is running${NC}\n"

# Check if required tools are installed
for cmd in python3 curl jq uuidgen; do
    if ! command -v $cmd &> /dev/null; then
        echo -e "${RED}Error: $cmd is not installed${NC}"
        exit 1
    fi
done

echo -e "${GREEN}✓ All required tools are installed${NC}\n"

# Generate JWT token
echo -e "${YELLOW}Generating JWT token...${NC}"
TOKEN=$(python3 << EOF
import jwt
import uuid
from datetime import datetime, timezone

secret = "$JWT_SECRET"
timestamp = datetime.now(timezone.utc).isoformat()
request_id = str(uuid.uuid4())

payload = {
    "timestamp": timestamp,
    "id": request_id
}

try:
    token = jwt.encode(payload, secret, algorithm="HS256")
    print(token)
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
    exit(1)
EOF
)

if [ -z "$TOKEN" ]; then
    echo -e "${RED}Failed to generate JWT token${NC}"
    echo "Install PyJWT: pip3 install pyjwt"
    exit 1
fi

echo -e "${GREEN}✓ JWT token generated${NC}"
echo -e "Token: ${TOKEN}\n"

# Prepare batch query request
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
REQUEST_ID=$(uuidgen)

echo -e "${YELLOW}Sending batch query request...${NC}"
echo -e "Timestamp: ${TIMESTAMP}"
echo -e "Request ID: ${REQUEST_ID}\n"

# Create request body
REQUEST_BODY=$(cat <<EOF
{
    "token": "$TOKEN",
    "timestamp": "$TIMESTAMP",
    "id": "$REQUEST_ID",
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
EOF
)

echo -e "${YELLOW}Request body:${NC}"
echo "$REQUEST_BODY" | jq .
echo ""

# Send request
echo -e "${YELLOW}Sending request to http://${HOST}:${HTTP_PORT}${BATCH_PATH}${NC}\n"

RESPONSE=$(curl -s -X POST "http://${HOST}:${HTTP_PORT}${BATCH_PATH}" \
    -H "Content-Type: application/json" \
    -d "$REQUEST_BODY")

# Check if response is valid JSON
if ! echo "$RESPONSE" | jq . > /dev/null 2>&1; then
    echo -e "${RED}Error: Invalid JSON response${NC}"
    echo "Response: $RESPONSE"
    exit 1
fi

echo -e "${GREEN}✓ Received valid JSON response${NC}\n"

echo -e "${YELLOW}Response:${NC}"
echo "$RESPONSE" | jq .

echo ""
echo -e "${GREEN}=== Test completed successfully! ===${NC}"

# Summary
NUM_QUERIES=$(echo "$RESPONSE" | jq 'length')
NUM_SUCCESS=$(echo "$RESPONSE" | jq '[.[] | select(.status == "success")] | length')
NUM_ERRORS=$(echo "$RESPONSE" | jq '[.[] | select(.status == "error")] | length')

echo ""
echo -e "${YELLOW}Summary:${NC}"
echo -e "  Total queries: ${NUM_QUERIES}"
echo -e "  Successful: ${GREEN}${NUM_SUCCESS}${NC}"
echo -e "  Errors: ${RED}${NUM_ERRORS}${NC}"

# Show query times
echo ""
echo -e "${YELLOW}Query times:${NC}"
echo "$RESPONSE" | jq -r '.[] | "\(.domain) (\(.type)): \(.query_time_ms)ms"'
