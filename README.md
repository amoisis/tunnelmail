# TunnelMail

A secure, production-ready HTTP-to-SMTP gateway for inbound webhook payloads (e.g., SendGrid inbound parse events). Implements industry-standard security practices, request rate limiting, concurrent request limits, and comprehensive observability metrics.

## Features

### Security
- **CRLF Injection Prevention**: All email headers sanitized to prevent header injection attacks
- **Email Address Validation**: RFC 5322 format validation on sender and recipient addresses
- **SSRF Prevention**: SMTP host validation prevents connections to private/internal IPs (127.0.0.1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- **Request Size Limits**: Configurable maximum request size (default 100MB) to prevent resource exhaustion
- **Graceful Shutdown**: SIGTERM/SIGINT signal handling with 30-second timeout for clean connection draining
- **Non-root Container**: Application runs as unprivileged `app` user in Docker

### Operational Features
- **Rate Limiting**: Per-IP rate limiting (default 10 requests/second) to prevent abuse
- **Concurrent Request Limiting**: Maximum concurrent request control (default 100) for resource management
- **SMTP Connection Timeout**: Configurable timeout for SMTP operations (default 30 seconds) with proper cleanup
- **Structured Logging**: Request metadata logging with response codes, client IPs, latencies
- **Health Check Endpoint**: GET `/health` endpoint for monitoring and Kubernetes liveness probes
- **Request Metrics**: In-memory metrics collection for observability (request count, error rate, latency)

### What It Does

1. Receives multipart form data from an inbound webhook
2. Validates sender and recipient email addresses
3. Extracts raw email message or builds MIME message from `text`, `html`, `headers`, and attachments
4. Sends message to configured SMTP server with timeout and proper resource cleanup
5. Returns JSON response indicating success or detailed error codes
6. Tracks metrics and logs requests for observability

## Environment Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `SMTP_HOST` | string | **Required** | SMTP server hostname or IP (e.g., `mailhog:1025`, `smtp.example.com:587`). Must not be a private IP. |
| `SMTP_EHLO_HOST` | string | container hostname | Hostname sent in the SMTP `EHLO`/`HELO` greeting. Many SMTP servers require a valid FQDN. Defaults to the container's hostname, falling back to `tunnelmail.local`. |
| `SMTP_ENVELOPE_FROM` | string | unset | Optional fixed envelope sender address used in the SMTP `MAIL FROM` command. Use this when the upstream SMTP server rejects the original sender domain (e.g. inbound webhook `from` field). The original `From:` header inside the message body is preserved. |
| `SMTP_USE_PROXY_PROTOCOL` | bool | `false` | When `true`, prepend a HAProxy PROXY Protocol v1 header on the SMTP connection so Stalwart sees the original client IP. Requires Stalwart's `proxyTrustedNetworks` to include TunnelMail's IP. |
| `HTTP_PORT` | int | `8080` | HTTP server listen port. Also exposed in Docker (see Dockerfile comment). |
| `SMTP_TIMEOUT` | int | `30` | SMTP operation timeout in seconds. Applies to connection establishment and command execution. |
| `MAX_REQUEST_SIZE` | int | `104857600` | Maximum request body size in bytes (default 100MB). Includes multipart form data and attachments. |
| `RATE_LIMIT_RPS` | float | `10` | Maximum requests per second per client IP. Enforced per unique source IP. |
| `MAX_CONCURRENT_REQUESTS` | int | `100` | Maximum concurrent requests allowed. Excess requests receive 429 (Too Busy) response. |
| `OTEL_COLLECTOR_ENDPOINT` | string | unset | Optional OTLP endpoint for exporting metrics, logs, and traces. Supports values like `http://collector:4318`. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | string | unset | Fallback OTLP endpoint if `OTEL_COLLECTOR_ENDPOINT` is not set. |

## API Reference

### POST /inbound

Receives webhook payload and forwards to SMTP server.

**Request Format**: `multipart/form-data`

**Expected Fields**:
- `from` (required): Sender email address (validated)
- `to` (required): Recipient email address(es), comma-separated (validated)
- `email` (optional): Raw RFC 2822 email message (takes precedence)
- `text` (optional): Plain text body (used if `email` not provided)
- `html` (optional): HTML body
- `headers` (optional): Additional email headers (CRLF-sanitized)
- `attachment*` (optional): File attachments

**Success Response** (200 OK):
```json
{
  "status": "accepted",
  "smtp_code": 250,
  "smtp_message": "2.0.0 Message queued with id ..."
}
```

**Error Response** (4xx/5xx):
```json
{
  "error": "human-readable error message",
  "code": "ERROR_CODE"
}
```

**Error Codes**:
- `RATE_LIMIT_EXCEEDED`: Client exceeded 10 requests/sec limit
- `TOO_BUSY`: Server at max concurrent request limit
- `PAYLOAD_TOO_LARGE`: Request body exceeds MAX_REQUEST_SIZE
- `INVALID_MULTIPART`: Malformed multipart form data
- `INVALID_ENVELOPE`: Invalid sender/recipient email addresses
- `BUILD_FAILED`: Failed to construct MIME message
- `SMTP_CONNECT_FAILED`: Cannot connect to SMTP server
- `SMTP_ERROR`: SMTP command failed (MAIL, RCPT, DATA)

### GET /health

Health check endpoint for monitoring and Kubernetes probes.

**Response** (200 OK):
```json
{
  "status": "ok",
  "metrics": {
    "total_requests": 1234,
    "total_errors": 12,
    "rate_limit_exceeded": 2,
    "too_busy": 1,
    "payload_too_large": 5,
    "total_latency_ms": 45000
  }
}
```

## Rate Limiting & Concurrency

### Rate Limiting
- Enforced per **client IP** (respects X-Forwarded-For header)
- Default: 10 requests/second per IP
- Clients exceeding limit receive `429 Too Many Requests` response
- Limit applies across all endpoints

### Concurrent Requests
- Global limit on simultaneous request processing
- Default: 100 concurrent requests
- Excess requests receive `429 Too Busy` response
- Allows graceful degradation under load

### Recommended Settings
- **Light traffic**: RATE_LIMIT_RPS=5, MAX_CONCURRENT_REQUESTS=50
- **Medium traffic**: RATE_LIMIT_RPS=10, MAX_CONCURRENT_REQUESTS=100 (default)
- **High traffic**: RATE_LIMIT_RPS=20, MAX_CONCURRENT_REQUESTS=200+

## Security Best Practices

### Configuration
1. **Set SMTP_HOST to public relay or trusted internal server** - Never allow user-controlled SMTP targets
2. **Disable public internet exposure** - Use firewall rules, VPN, or private networks
3. **Monitor rate limits and metrics** - Alert on unexpected error spikes
4. **Rotate webhook tokens** (in caller) - If using webhook authentication
5. **Use HTTPS reverse proxy** - Terminate TLS in front of this gateway

### Deployment
1. **Run in container with resource limits** - Set memory/CPU cgroups
2. **Use non-root user** (automatic in Docker)
3. **Isolate from database/sensitive services** - Network segmentation
4. **Log and monitor** - Send logs to centralized logging system
5. **Regular dependency updates** - Dependabot configured for Go modules

### Email Message Validation
- Sender and recipient addresses validated for basic RFC 5322 format
- All email headers sanitized to prevent CRLF injection
- No TLS/authentication support (assumes internal trusted SMTP server)
- Maximum request size limits prevent unbounded memory usage

## Deployment

### Local Development

Run directly:
```bash
SMTP_HOST=mailhog:1025 go run ./src
```

Using Docker Compose:
```bash
docker compose up -d
```

### Docker Deployment

Build image:
```bash
docker build -t tunnelmail:latest .
```

Run container:
```bash
docker run -d \
  -e SMTP_HOST=mail.example.com:587 \
  -e HTTP_PORT=8080 \
  -p 8080:8080 \
  tunnelmail:latest
```

### Kubernetes Deployment

Example Deployment manifest:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tunnelmail
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: gateway
        image: tunnelmail:latest
        ports:
        - containerPort: 8080
        env:
        - name: SMTP_HOST
          value: "smtp-relay.default.svc.cluster.local:25"
        - name: HTTP_PORT
          value: "8080"
        - name: RATE_LIMIT_RPS
          value: "10"
        - name: MAX_CONCURRENT_REQUESTS
          value: "100"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 512Mi
```

## Observability

The gateway configures OpenTelemetry for metrics, logs, and traces when an OTLP endpoint is provided. Metrics and logs are emitted through the OTLP HTTP exporter, and request spans are created for `/inbound` traffic.

### Running with a local collector

Example with a local OTel collector:

```bash
OTEL_COLLECTOR_ENDPOINT=http://localhost:4318 SMTP_HOST=mailhog:1025 go run ./src
```

Then verify that spans, logs, and metrics appear in your collector backend or its UI.

## Testing

### Unit Tests

Run all unit tests:
```bash
go test ./src -v
```

Run with coverage:
```bash
go test ./src -v -cover
```

Run specific test:
```bash
go test ./src -v -run TestIsValidEmail
```

Benchmarks:
```bash
go test ./src -bench=. -benchmem
```

### Integration Testing

Use provided test script with sample payload:
```bash
./test.sh http://localhost:8080/inbound
```

Or curl directly:
```bash
curl -X POST http://localhost:8080/inbound \
  -F "from=sender@example.com" \
  -F "to=recipient@example.com" \
  -F "text=Hello World"
```

### E2E Testing with Docker Compose

```bash
# Start services
docker compose up -d

# Run test
./test.sh http://localhost:8080/inbound

# Check MailHog UI
open http://localhost:8025

# Cleanup
docker compose down
```

## Troubleshooting

### "SMTP_HOST cannot be a private IP" Error
**Cause**: SMTP_HOST is set to a private IP (127.0.0.1, 10.x.x.x, 172.16-31.x.x, 192.168.x.x)
**Solution**: Use public SMTP relay or hostname instead

### "rate limit exceeded" Response
**Cause**: Client IP exceeded RATE_LIMIT_RPS threshold
**Solution**: Increase RATE_LIMIT_RPS env var or implement batching on client side

### "service too busy" Response (429)
**Cause**: Server at MAX_CONCURRENT_REQUESTS limit
**Solution**: Increase MAX_CONCURRENT_REQUESTS or scale horizontally

### "request body too large" Response
**Cause**: Request with attachments exceeds MAX_REQUEST_SIZE
**Solution**: Increase MAX_REQUEST_SIZE or reduce attachment sizes

### "SMTP connection failed" Error
**Cause**: Cannot reach SMTP server
**Solution**: Verify SMTP_HOST, network connectivity, firewall rules

### Slow Latencies in Metrics
**Cause**: SMTP server slow to respond
**Solution**: Check SMTP server logs, reduce SMTP_TIMEOUT, investigate network latency

## Metrics & Observability

The `/health` endpoint exposes cumulative metrics:

```json
{
  "status": "ok",
  "metrics": {
    "total_requests": 5432,
    "total_errors": 45,
    "rate_limit_exceeded": 12,
    "too_busy": 5,
    "payload_too_large": 8,
    "total_latency_ms": 234567
  }
}
```

Calculate average latency: `total_latency_ms / total_requests`
Error rate: `total_errors / total_requests`

For production monitoring, integrate with:
- **Prometheus**: Scrape /health endpoint
- **Grafana**: Create dashboards on metrics
- **ELK/Splunk**: Parse structured logs

## Architecture

```
HTTP Request (multipart form)
    ↓
[Rate Limit Check] → Rate limited? → 429
    ↓
[Concurrency Limit] → Too busy? → 429
    ↓
[Size Limit] → Too large? → 413
    ↓
[Parse & Validate Email] → Invalid? → 400
    ↓
[Build/Extract Message] → Error? → 400
    ↓
[SMTP Connection] → Failed? → 502
    ↓
[SMTP MAIL/RCPT/DATA] → Error? → 502
    ↓
[Cleanup & Log] → 200 OK
```

## Contributing

- Follow Go code style guidelines
- Add tests for new functionality
- Update documentation for new env vars or features
- Run tests before submitting changes

## License

MIT (or your chosen license)

## Dependency Updates

Dependabot is configured for:
- Go modules (go.mod)
- Docker base images (Dockerfile)
- GitHub Actions workflows (.github/workflows/)

## See Also

- [Go net/smtp documentation](https://pkg.go.dev/net/smtp)
- [RFC 5322 - Internet Message Format](https://tools.ietf.org/html/rfc5322)
- [SendGrid Inbound Parse Webhook](https://docs.sendgrid.com/for-developers/parsing-webhook)
