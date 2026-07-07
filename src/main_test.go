package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Test CRLF Injection Prevention
func TestSanitizeHeader(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal header", "normal header"},
		{"header\nwith\nnewlines", "headerwithnewlines"},
		{"header\rwith\rcarriage", "headerwithcarriage"},
		{"header\r\nwith\r\nboth", "headerwithboth"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("sanitize_%s", tt.input), func(t *testing.T) {
			result := sanitizeHeader(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeHeader(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// Test CRLF normalization for raw email messages
func TestNormalizeCRLF(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"line1\nline2", "line1\r\nline2"},
		{"line1\r\nline2", "line1\r\nline2"},
		{"line1\rline2", "line1\r\nline2"},
		{"line1\nline2\rline3", "line1\r\nline2\r\nline3"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("normalize_%q", tt.input), func(t *testing.T) {
			result := normalizeCRLF(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeCRLF(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// Test Email Validation
func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		email    string
		expected bool
	}{
		{"user@example.com", true},
		{"test.user@domain.co.uk", true},
		{"a@b.c", true},
		{"", false},
		{"noemail", false},
		{"@example.com", false},
		{"user@", false},
		{"user @example.com", true}, // trimmed
		{"user@domain", false},       // no dot in domain
		{"user@@example.com", false}, // multiple @
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("validate_%s", tt.email), func(t *testing.T) {
			result := isValidEmail(tt.email)
			if result != tt.expected {
				t.Errorf("isValidEmail(%q) = %v, want %v", tt.email, result, tt.expected)
			}
		})
	}
}

// Test Environment Variable Parsing
func TestParseEnvInt(t *testing.T) {
	tests := []struct {
		name        string
		envKey      string
		defaultVal  int
		setEnv      string
		expected    int
	}{
		{"missing env, use default", "TEST_VAR_MISSING", 42, "", 42},
		{"valid number", "TEST_VAR_VALID", 42, "100", 100},
		{"invalid number", "TEST_VAR_INVALID", 42, "abc", 42},
		{"negative number", "TEST_VAR_NEGATIVE", 42, "-5", 42},
		{"zero", "TEST_VAR_ZERO", 42, "0", 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.envKey, tt.setEnv)
			result := parseEnvInt(tt.envKey, tt.defaultVal)
			if result != tt.expected {
				t.Errorf("parseEnvInt(%q, %d) = %d, want %d", tt.envKey, tt.defaultVal, result, tt.expected)
			}
		})
	}
}

// Test Private IP Detection (SSRF Prevention)
func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
	}{
		{"127.0.0.1", true},
		{"localhost", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		{"8.8.8.8", false},
		{"example.com", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("private_%s", tt.ip), func(t *testing.T) {
			result := isPrivateIP(tt.ip)
			if result != tt.expected {
				t.Errorf("isPrivateIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

// Test Rate Limiter
func TestRateLimiter(t *testing.T) {
	rl := &RateLimiter{limiters: make(map[string]*time.Time)}

	// First request should pass
	if !rl.Allow("192.168.1.1", 1.0) {
		t.Error("first request from IP should be allowed")
	}

	// Second immediate request should fail (rate limited)
	if rl.Allow("192.168.1.1", 1.0) {
		t.Error("second immediate request should be rate limited")
	}

	// Different IP should be allowed
	if !rl.Allow("192.168.1.2", 1.0) {
		t.Error("first request from different IP should be allowed")
	}
}

// Test Metrics Collection
func TestMetrics(t *testing.T) {
	metrics := &Metrics{}

	if metrics.requestCount != 0 {
		t.Error("initial request count should be 0")
	}

	metrics.IncrementRequest()
	stats := metrics.GetStats()
	if stats["total_requests"] != 1 {
		t.Errorf("after IncrementRequest, total_requests = %d, want 1", stats["total_requests"])
	}

	metrics.IncrementError()
	stats = metrics.GetStats()
	if stats["total_errors"] != 1 {
		t.Errorf("after IncrementError, total_errors = %d, want 1", stats["total_errors"])
	}

	metrics.IncrementRateLimit()
	stats = metrics.GetStats()
	if stats["rate_limit_exceeded"] != 1 {
		t.Errorf("after IncrementRateLimit, rate_limit_exceeded = %d, want 1", stats["rate_limit_exceeded"])
	}

	metrics.AddLatency(100)
	metrics.AddLatency(50)
	stats = metrics.GetStats()
	if stats["total_latency_ms"] != 150 {
		t.Errorf("after AddLatency(100, 50), total_latency_ms = %d, want 150", stats["total_latency_ms"])
	}
}

// Test Error Response Format
func TestErrorResponse(t *testing.T) {
	rr := httptest.NewRecorder()

	sendErrorResponse(rr, http.StatusBadRequest, "TEST_ERROR", "test error message")

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", status, http.StatusBadRequest)
	}

	expectedCT := "application/json"
	if ct := rr.Header().Get("Content-Type"); ct != expectedCT {
		t.Errorf("Content-Type = %s, want %s", ct, expectedCT)
	}

	if !strings.Contains(rr.Body.String(), "TEST_ERROR") {
		t.Errorf("response body should contain error code, got %s", rr.Body.String())
	}

	if !strings.Contains(rr.Body.String(), "test error message") {
		t.Errorf("response body should contain error message, got %s", rr.Body.String())
	}
}

// Test Header Parsing - Valid Address
func TestParseEnvelopeValid(t *testing.T) {
	// Create a request with properly formatted multipart form data
	body := `--boundary123
Content-Disposition: form-data; name="from"

sender@example.com
--boundary123
Content-Disposition: form-data; name="to"

recipient1@example.com,recipient2@example.com
--boundary123--`

	req := httptest.NewRequest("POST", "/inbound", strings.NewReader(body))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=boundary123")

	err := req.ParseMultipartForm(1 << 20)
	if err != nil {
		t.Skipf("setup error: %v", err)
	}

	from, recipients, err := parseEnvelope(req, JSONPayload{})
	if err != nil {
		t.Errorf("parseEnvelope should not error for valid input: %v", err)
	}

	if from != "sender@example.com" {
		t.Errorf("from = %q, want %q", from, "sender@example.com")
	}

	if len(recipients) != 2 {
		t.Errorf("recipients count = %d, want 2", len(recipients))
	}
}

// Test JSON payload with envelope.to as a single string (Cloudflare Worker format)
func TestBuildMessageWrapsPlainTextRawBodyWithHeaders(t *testing.T) {
	req := httptest.NewRequest("POST", "/inbound", nil)
	msg, err := buildMessage(req, "Hello world", "sender@example.com", []string{"recipient@example.com"}, "203.0.113.1", JSONPayload{})
	if err != nil {
		t.Fatalf("buildMessage returned error: %v", err)
	}
	text := string(msg)
	if !strings.Contains(text, "From: sender@example.com") {
		t.Fatalf("expected From header in message, got %q", text)
	}
	if !strings.Contains(text, "To: recipient@example.com") {
		t.Fatalf("expected To header in message, got %q", text)
	}
	if !strings.Contains(text, "Date:") {
		t.Fatalf("expected Date header in message, got %q", text)
	}
	if !strings.Contains(text, "Message-ID:") {
		t.Fatalf("expected Message-ID header in message, got %q", text)
	}
	if !strings.Contains(text, "\r\n\r\nHello world") {
		t.Fatalf("expected header/body separator before raw body, got %q", text)
	}
}

func TestParseEnvelopeJSONStringTo(t *testing.T) {
	jsonBody := `{
		"envelope": {
			"from": "sender@example.com",
			"to": "recipient@example.com"
		}
	}`

	req := httptest.NewRequest("POST", "/inbound", strings.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	var payload JSONPayload
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		t.Fatalf("failed to decode JSON payload: %v", err)
	}

	from, recipients, err := parseEnvelope(req, payload)
	if err != nil {
		t.Errorf("parseEnvelope should not error for JSON payload: %v", err)
	}
	if from != "sender@example.com" {
		t.Errorf("from = %q, want %q", from, "sender@example.com")
	}
	if len(recipients) != 1 || recipients[0] != "recipient@example.com" {
		t.Errorf("recipients = %v, want [recipient@example.com]", recipients)
	}
}

func TestDescribeSMTPHandshakeErrorIncludesProxyHint(t *testing.T) {
	err := &net.DNSError{Err: "i/o timeout", Name: "10.0.10.3", Server: "10.0.10.3:25"}
	wrapped := describeSMTPHandshakeError("10.0.10.3:25", false, err)
	msg := wrapped.Error()

	if !strings.Contains(msg, "SMTP_USE_PROXY_PROTOCOL") {
		t.Fatalf("expected timeout message to mention SMTP_USE_PROXY_PROTOCOL, got %q", msg)
	}
	if !strings.Contains(msg, "PROXY Protocol") {
		t.Fatalf("expected timeout message to mention PROXY Protocol, got %q", msg)
	}
}

func TestBuildProxyHeaderUsesIPv4MappedIPv6ForMixedFamilies(t *testing.T) {
	header, err := buildProxyHeader("2a01:111:f403:c40d::4", "10.0.10.16:25")
	if err != nil {
		t.Fatalf("buildProxyHeader returned error: %v", err)
	}
	if header != "PROXY TCP6 2a01:111:f403:c40d::4 ::ffff:10.0.10.16 0 25\r\n" {
		t.Fatalf("unexpected proxy header: %q", header)
	}
}

// Test Client IP Detection
func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name      string
		remoteAddr string
		xffHeader string
		expected  string
	}{
		{"direct connection", "192.168.1.100:1234", "", "192.168.1.100"},
		{"with X-Forwarded-For", "127.0.0.1:8080", "203.0.113.1, 203.0.113.2", "203.0.113.1"},
		{"X-Forwarded-For single", "127.0.0.1:8080", "203.0.113.1", "203.0.113.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xffHeader != "" {
				req.Header.Set("X-Forwarded-For", tt.xffHeader)
			}

			result := getClientIP(req)
			if result != tt.expected {
				t.Errorf("getClientIP() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// Test Semaphore (Concurrent Limiting)
func TestSemaphore(t *testing.T) {
	sem := NewSemaphore(2)

	if !sem.Acquire() {
		defer sem.Release()
		t.Error("first acquire should succeed")
	}

	if !sem.Acquire() {
		defer sem.Release()
		t.Error("second acquire should succeed")
	}

	if sem.Acquire() {
		t.Error("third acquire should fail when semaphore is full")
	}
}

// Test Request Logger
func TestRequestLogger(t *testing.T) {
	logger := &RequestLogger{
		method:    "POST",
		path:      "/inbound",
		remoteIP:  "192.168.1.1",
		startTime: time.Now(),
	}

	if logger.method != "POST" {
		t.Errorf("method = %s, want POST", logger.method)
	}

	if logger.remoteIP != "192.168.1.1" {
		t.Errorf("remoteIP = %s, want 192.168.1.1", logger.remoteIP)
	}

	// Log should not panic
	logger.Log(http.StatusOK, nil)
}

// Benchmark Sanitize Header
func BenchmarkSanitizeHeader(b *testing.B) {
	input := "From: sender@example.com\r\nTo: recipient@example.com\r\n"
	for i := 0; i < b.N; i++ {
		sanitizeHeader(input)
	}
}

// Benchmark Email Validation
func BenchmarkIsValidEmail(b *testing.B) {
	email := "user.name+tag@example.co.uk"
	for i := 0; i < b.N; i++ {
		isValidEmail(email)
	}
}

// Benchmark Rate Limiter Allow
func BenchmarkRateLimiterAllow(b *testing.B) {
	rl := &RateLimiter{limiters: make(map[string]*time.Time)}
	for i := 0; i < b.N; i++ {
		rl.Allow("192.168.1.1", 10.0)
	}
}

// Benchmark Metrics
func BenchmarkMetricsIncrement(b *testing.B) {
	m := &Metrics{}
	for i := 0; i < b.N; i++ {
		m.IncrementRequest()
		m.IncrementError()
		m.AddLatency(100)
	}
}
