#!/usr/bin/env bash
set -euo pipefail

URL="${1:-http://localhost:8080/inbound}"

curl -X POST "$URL" \
  -H "Content-Type: multipart/form-data; boundary=boundary123" \
  --data-binary @test-payload.txt
