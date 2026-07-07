#!/usr/bin/env bash
set -euo pipefail

URL="${1:-https://tunnelmail.moisis.net/inbound}"

curl -X POST "$URL" \
  -H "Content-Type: multipart/form-data; boundary=boundary123" \
  --data-binary @test-payload.txt
