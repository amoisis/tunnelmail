package main

import (
	"encoding/json"
	"fmt"
	"io"
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
		{"user @example.com", true},  // trimmed
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
		name       string
		envKey     string
		defaultVal int
		setEnv     string
		expected   int
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

func TestBuildMessagePreservesRawEmailBytes(t *testing.T) {
	raw := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Hello\r\n\r\nBody line 1\r\nBody line 2\r\n"
	req := httptest.NewRequest("POST", "/inbound", nil)
	msg, err := buildMessage(req, raw, "sender@example.com", []string{"recipient@example.com"}, "203.0.113.1", JSONPayload{})
	if err != nil {
		t.Fatalf("buildMessage returned error: %v", err)
	}
	if string(msg) != raw {
		t.Fatalf("expected raw message bytes to be preserved exactly, got %q want %q", string(msg), raw)
	}
}

func TestLooksLikeRFC5322MessageRejectsPlainTextBody(t *testing.T) {
	if looksLikeRFC5322Message("Hello world\n\nThis is body text") {
		t.Fatal("expected plain text body to be treated as non-RFC input")
	}
}

func TestEnsureRequiredHeadersIgnoresBodyText(t *testing.T) {
	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\n\r\nDate: fake in body\r\n"
	result := ensureRequiredHeaders(msg, "sender@example.com")
	if !strings.Contains(result, "\r\nDate: ") {
		t.Fatalf("expected Date header to be injected, got %q", result)
	}
	if !strings.Contains(result, "\r\nMessage-ID: ") {
		t.Fatalf("expected Message-ID header to be injected, got %q", result)
	}
}

func TestBuildMessageDoesNotTrimRawEmail(t *testing.T) {
	raw := "\r\nFrom: sender@example.com\r\nTo: recipient@example.com\r\n\r\n"
	req := httptest.NewRequest("POST", "/inbound", nil)
	msg, err := buildMessage(req, raw, "sender@example.com", []string{"recipient@example.com"}, "203.0.113.1", JSONPayload{})
	if err != nil {
		t.Fatalf("buildMessage returned error: %v", err)
	}
	if string(msg) != raw {
		t.Fatalf("expected raw message bytes to be preserved exactly, got %q want %q", string(msg), raw)
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
	// When source is IPv6 but destination resolves to IPv4, use "::" for the
	// destination — the ::ffff: form is technically valid but rejected by some
	// PROXY parsers (including Stalwart) in a TCP6 context.
	if header != "PROXY TCP6 2a01:111:f403:c40d::4 :: 0 25\r\n" {
		t.Fatalf("unexpected proxy header: %q", header)
	}
}

// Test Client IP Detection
func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		xffHeader  string
		expected   string
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

// mockSMTPServer starts a fake SMTP server that sends the provided script lines
// to the client, then reads commands and replies with the given responses.
// It returns the listener address and a channel that receives all commands the
// server received (in order).
func mockSMTPServer(t *testing.T, script func(conn net.Conn)) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mockSMTPServer listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		script(conn)
	}()
	return ln.Addr().String()
}

func writeLine(conn net.Conn, s string) {
	io.WriteString(conn, s+"\r\n")
}

func readLine(conn net.Conn) string {
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	return strings.TrimRight(string(buf[:n]), "\r\n")
}

// TestSMTPSession_RFC_EHLO tests a standard RFC-compliant EHLO response where
// the banner is the first line with a dash and capabilities follow.
func TestSMTPSession_RFC_EHLO(t *testing.T) {
	addr := mockSMTPServer(t, func(conn net.Conn) {
		writeLine(conn, "220 test.example.com ESMTP ready")
		readLine(conn) // consume EHLO
		// Standard RFC multi-line EHLO: banner first with dash, last cap with space
		writeLine(conn, "250-test.example.com Hello")
		writeLine(conn, "250-STARTTLS")
		writeLine(conn, "250-8BITMIME")
		writeLine(conn, "250 SIZE 104857600")
		readLine(conn) // MAIL FROM
		writeLine(conn, "250 2.1.0 OK")
		readLine(conn) // RCPT TO
		writeLine(conn, "250 2.1.5 OK")
		readLine(conn) // DATA
		writeLine(conn, "354 Go ahead")
		// client writes message + dot
		buf := make([]byte, 4096)
		for {
			n, _ := conn.Read(buf)
			if strings.Contains(string(buf[:n]), "\r\n.\r\n") {
				break
			}
		}
		writeLine(conn, "250 2.0.0 queued as abc123")
		readLine(conn) // QUIT
		writeLine(conn, "221 Bye")
	})

	sess, err := newSMTPSession(addr, "test.local", "", false, 5*time.Second)
	if err != nil {
		t.Fatalf("newSMTPSession: %v", err)
	}
	defer sess.Close()

	if err := sess.Mail("from@example.com"); err != nil {
		t.Fatalf("Mail: %v", err)
	}
	if err := sess.Rcpt("to@example.com"); err != nil {
		t.Fatalf("Rcpt: %v", err)
	}
	wc, err := sess.Data()
	if err != nil {
		t.Fatalf("Data (expected 354 go-ahead): %v", err)
	}
	io.WriteString(wc, "Subject: test\r\n\r\nHello\r\n")
	wc.Close()
	code, msg, err := sess.readFinalDataResponse()
	if err != nil {
		t.Fatalf("readFinalDataResponse: %v", err)
	}
	if code != 250 {
		t.Errorf("expected final DATA code 250, got %d %s", code, msg)
	}
}

// TestSMTPSession_Stalwart_EHLO tests the real Stalwart wire format confirmed
// by raw packet capture. Stalwart is RFC-compliant: "250-" for all lines except
// the last "250 8BITMIME". drainEHLO must read all 11 lines without a timeout.
func TestSMTPSession_Stalwart_EHLO(t *testing.T) {
	addr := mockSMTPServer(t, func(conn net.Conn) {
		writeLine(conn, "220 stalwart.example.com ESMTP Stalwart Mail Server")
		readLine(conn) // consume EHLO
		// Real Stalwart format (from raw packet capture): banner with dash first,
		// capabilities with dashes, final "250 8BITMIME" with space.
		writeLine(conn, "250-stalwart.example.com you had me at EHLO")
		writeLine(conn, "250-STARTTLS")
		writeLine(conn, "250-SMTPUTF8")
		writeLine(conn, "250-SIZE 104857600")
		writeLine(conn, "250-REQUIRETLS")
		writeLine(conn, "250-PIPELINING")
		writeLine(conn, "250-NO-SOLICITING")
		writeLine(conn, "250-ENHANCEDSTATUSCODES")
		writeLine(conn, "250-CHUNKING")
		writeLine(conn, "250-BINARYMIME")
		writeLine(conn, "250 8BITMIME")
		readLine(conn) // MAIL FROM
		writeLine(conn, "250 2.1.0 OK")
		readLine(conn) // RCPT TO
		writeLine(conn, "250 2.1.5 OK")
		readLine(conn) // DATA
		writeLine(conn, "354 Go ahead")
		buf := make([]byte, 4096)
		for {
			n, _ := conn.Read(buf)
			if strings.Contains(string(buf[:n]), "\r\n.\r\n") {
				break
			}
		}
		writeLine(conn, "250 2.0.0 queued as xyz789")
		readLine(conn) // QUIT
		writeLine(conn, "221 Bye")
	})

	sess, err := newSMTPSession(addr, "tunnelmail.local", "", false, 5*time.Second)
	if err != nil {
		t.Fatalf("newSMTPSession: %v", err)
	}
	defer sess.Close()

	if err := sess.Mail("sender@westpac.com.au"); err != nil {
		t.Fatalf("Mail: %v — EHLO left capability lines in the buffer, shifting all responses", err)
	}
	if err := sess.Rcpt("ariel@moisis.net"); err != nil {
		t.Fatalf("Rcpt: %v", err)
	}
	wc, err := sess.Data()
	if err != nil {
		t.Fatalf("Data (expected 354 go-ahead, got something else — the RCPT response is still in buffer): %v", err)
	}
	io.WriteString(wc, "Subject: test\r\n\r\nHello\r\n")
	wc.Close()
	code, msg, err := sess.readFinalDataResponse()
	if err != nil {
		t.Fatalf("readFinalDataResponse: %v", err)
	}
	if code != 250 {
		t.Errorf("expected final DATA code 250, got %d %s", code, msg)
	}
}

// TestSMTPSession_ProxyRejection tests the exact failure seen in production:
// Stalwart is NOT configured for PROXY protocol, so the PROXY header is
// rejected. The server sends "220 greeting\r\n500 Invalid command.\r\n" in a
// single TCP write. textproto's bufio.Reader buffers the 500 alongside the 220.
// We must drain that 500 after reading the 220, then EHLO must succeed normally.
func TestSMTPSession_ProxyRejection(t *testing.T) {
	addr := mockSMTPServer(t, func(conn net.Conn) {
		// Simulate: client sends "PROXY TCP6 ...\r\n", server replies with
		// greeting + rejection in the same write (one TCP segment).
		readLine(conn)                                                              // consume PROXY header
		io.WriteString(conn, "220 stalwart.example.com ESMTP ready\r\n500 5.5.1 Invalid command.\r\n") //nolint:errcheck
		readLine(conn) // consume EHLO
		// Normal EHLO response
		writeLine(conn, "250-stalwart.example.com you had me at EHLO")
		writeLine(conn, "250-STARTTLS")
		writeLine(conn, "250 8BITMIME")
		readLine(conn) // MAIL FROM
		writeLine(conn, "250 2.1.0 OK")
		readLine(conn) // RCPT TO
		writeLine(conn, "250 2.1.5 OK")
		readLine(conn) // DATA
		writeLine(conn, "354 Go ahead")
		buf := make([]byte, 4096)
		for {
			n, _ := conn.Read(buf)
			if strings.Contains(string(buf[:n]), "\r\n.\r\n") {
				break
			}
		}
		writeLine(conn, "250 2.0.0 OK")
		readLine(conn) // QUIT
		writeLine(conn, "221 Bye")
	})

	// useProxyProtocol=true — the session will write a PROXY header.
	// The mock server reads it and sends 220+500 together.
	sess, err := newSMTPSession(addr, "tunnelmail.local", "2a01:111:f403:c40e::1", true, 5*time.Second)
	if err != nil {
		t.Fatalf("newSMTPSession: %v (500 after 220 was not drained or EHLO failed)", err)
	}
	defer sess.Close()

	if err := sess.Mail("sender@westpac.com.au"); err != nil {
		t.Fatalf("Mail: %v", err)
	}
	if err := sess.Rcpt("ariel@moisis.net"); err != nil {
		t.Fatalf("Rcpt: %v", err)
	}
	wc, err := sess.Data()
	if err != nil {
		t.Fatalf("Data: expected 354, got error (likely 1-line response offset): %v", err)
	}
	io.WriteString(wc, "Subject: test\r\n\r\nHello\r\n")
	wc.Close()
	code, msg, err := sess.readFinalDataResponse()
	if err != nil {
		t.Fatalf("readFinalDataResponse: %v", err)
	}
	if code != 250 {
		t.Errorf("expected 250, got %d %s", code, msg)
	}
}
