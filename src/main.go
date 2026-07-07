package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otelLog "go.opentelemetry.io/otel/log"
	otelGlobal "go.opentelemetry.io/otel/log/global"
	otelMetric "go.opentelemetry.io/otel/metric"
	logsdk "go.opentelemetry.io/otel/sdk/log"
	metricsdk "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// Task 1: CRLF Injection Prevention
func sanitizeHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return s
}

// normalizeCRLF converts line endings to CRLF, which is required by RFC 5321
// for the SMTP DATA phase. It handles LF-only and mixed CRLF/LF input.
func normalizeCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

// injectHeader inserts a header into an RFC 5322 message after the existing
// headers and before the body separator. The message is assumed to use CRLF
// line endings.
func injectHeader(message, name, value string) string {
	idx := strings.Index(message, "\r\n\r\n")
	if idx == -1 {
		return message + "\r\n" + name + ": " + value + "\r\n"
	}
	return message[:idx+2] + name + ": " + value + message[idx+2:]
}

// injectAuthResults adds X-AuthResults-* and X-Spam-Score headers from the
// upstream worker into a raw email message when they are not already present.
func injectAuthResults(message string, payload JSONPayload) string {
	if payload.AuthResults.SPF != "" && !strings.Contains(message, "\nX-AuthResults-SPF:") {
		message = injectHeader(message, "X-AuthResults-SPF", sanitizeHeader(payload.AuthResults.SPF))
	}
	if payload.AuthResults.DKIM != "" && !strings.Contains(message, "\nX-AuthResults-DKIM:") {
		message = injectHeader(message, "X-AuthResults-DKIM", sanitizeHeader(payload.AuthResults.DKIM))
	}
	if payload.SpamScore != "" && !strings.Contains(message, "\nX-Spam-Score:") {
		message = injectHeader(message, "X-Spam-Score", sanitizeHeader(payload.SpamScore))
	}
	return message
}

// ensureRequiredHeaders adds Date and Message-ID headers if they are missing
// from a raw email message. Spam filters heavily penalize messages without
// these headers.
func ensureRequiredHeaders(message, from string) string {
	if !strings.Contains(message, "\nDate:") && !strings.HasPrefix(message, "Date:") {
		message = injectHeader(message, "Date", time.Now().UTC().Format(time.RFC1123Z))
	}
	if !strings.Contains(message, "\nMessage-ID:") && !strings.HasPrefix(message, "Message-ID:") {
		domain := "localhost"
		if from != "" {
			parts := strings.Split(from, "@")
			if len(parts) == 2 && parts[1] != "" {
				domain = parts[1]
			}
		}
		message = injectHeader(message, "Message-ID", fmt.Sprintf("<gateway.%d@%s>", time.Now().UnixNano(), domain))
	}
	return message
}

// Task 2: Email Validation
func isValidEmail(email string) bool {
	email = strings.TrimSpace(email)
	if email == "" {
		return false
	}
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	localPart := strings.TrimSpace(parts[0])
	domain := strings.TrimSpace(parts[1])
	if localPart == "" || domain == "" {
		return false
	}
	if !strings.Contains(domain, ".") {
		return false
	}
	return true
}

// Task 3 & 5: Request/SMTP size limits
func parseEnvInt(key string, defaultVal int) int {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	parsed, err := strconv.Atoi(val)
	if err != nil {
		log.Printf("invalid %s: %v, using default %d", key, err, defaultVal)
		return defaultVal
	}
	if parsed <= 0 {
		log.Printf("%s must be positive, using default %d", key, defaultVal)
		return defaultVal
	}
	return parsed
}

func parseEnvInt64(key string, defaultVal int64) int64 {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	parsed, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		log.Printf("invalid %s: %v, using default %d", key, err, defaultVal)
		return defaultVal
	}
	if parsed <= 0 {
		log.Printf("%s must be positive, using default %d", key, defaultVal)
		return defaultVal
	}
	return parsed
}

// reverseDNS looks up the PTR record for an IP with a short timeout.
// It returns the first resolved hostname or an empty string on failure.
func reverseDNS(ipStr string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var names []string
	var err error
	done := make(chan struct{})
	go func() {
		names, err = net.LookupAddr(ipStr)
		close(done)
	}()

	select {
	case <-done:
		if err != nil || len(names) == 0 {
			return ""
		}
		name := strings.TrimSuffix(names[0], ".")
		if name == "" {
			return ""
		}
		return name
	case <-ctx.Done():
		return ""
	}
}

// buildProxyHeader constructs a HAProxy PROXY Protocol v1 header so the
// upstream SMTP server can see the original client IP. The destination address
// is resolved from the SMTP host; if it cannot be determined, a placeholder is
// used. Source port is unknown and reported as 0.
func buildProxyHeader(srcIP, dstHost string) (string, error) {
	src := net.ParseIP(srcIP)
	if src == nil {
		return "", fmt.Errorf("invalid source IP: %s", srcIP)
	}

	dstHostOnly, dstPortStr, err := net.SplitHostPort(dstHost)
	if err != nil {
		dstHostOnly = dstHost
		dstPortStr = "25"
	}
	dstPort, err := strconv.Atoi(dstPortStr)
	if err != nil {
		dstPort = 25
	}

	var dst net.IP
	if parsed := net.ParseIP(dstHostOnly); parsed != nil {
		dst = parsed
	} else {
		if ips, err := net.LookupIP(dstHostOnly); err == nil && len(ips) > 0 {
			dst = ips[0]
		}
	}

	var family, dstStr string
	if src.To4() != nil {
		family = "TCP4"
		if dst != nil && dst.To4() != nil {
			dstStr = dst.String()
		} else {
			dstStr = "0.0.0.0"
		}
	} else {
		family = "TCP6"
		if dst != nil {
			dstStr = dst.String()
		} else {
			dstStr = "::"
		}
	}

	return fmt.Sprintf("PROXY %s %s %s 0 %d\r\n", family, src.String(), dstStr, dstPort), nil
}

// smtpResult holds the parsed response from a successful DATA acceptance so
// the upstream queue ID and SMTP code can be returned to the HTTP caller.
type smtpResult struct {
	Code    int    `json:"smtp_code"`
	Message string `json:"smtp_message"`
}

// smtpSession is a minimal SMTP client that gives us full control over the
// command/response stream, including the ability to capture the queue ID
// returned after the DATA terminator.
type smtpSession struct {
	conn    net.Conn
	text    *textproto.Conn
	timeout time.Duration
}

func newSMTPSession(host, localName, clientIP string, useProxyProtocol bool, timeout time.Duration) (*smtpSession, error) {
	conn, err := net.DialTimeout("tcp", host, timeout)
	if err != nil {
		return nil, err
	}

	if useProxyProtocol && clientIP != "" {
		proxyHeader, err := buildProxyHeader(clientIP, host)
		if err == nil {
			log.Printf("sending PROXY header: %q", strings.TrimSpace(proxyHeader))
			if _, writeErr := conn.Write([]byte(proxyHeader)); writeErr != nil {
				conn.Close()
				return nil, fmt.Errorf("failed to write PROXY header: %w", writeErr)
			}
		} else {
			log.Printf("invalid client IP for PROXY protocol: %v", err)
		}
	}

	s := &smtpSession{
		conn:    conn,
		text:    textproto.NewConn(conn),
		timeout: timeout,
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		s.Close()
		return nil, err
	}

	// Read the server banner.
	if _, _, err := s.text.ReadResponse(220); err != nil {
		s.Close()
		return nil, err
	}

	// Send EHLO/HELO.
	if err := s.hello(localName); err != nil {
		s.Close()
		return nil, err
	}

	return s, nil
}

func (s *smtpSession) hello(localName string) error {
	if err := s.text.PrintfLine("EHLO %s", localName); err != nil {
		return err
	}
	if _, _, err := s.text.ReadResponse(250); err != nil {
		// Fall back to HELO if EHLO is not supported.
		if err := s.text.PrintfLine("HELO %s", localName); err != nil {
			return err
		}
		_, _, err = s.text.ReadResponse(250)
		return err
	}
	return nil
}

func (s *smtpSession) Mail(from string) error {
	if err := s.text.PrintfLine("MAIL FROM:<%s>", from); err != nil {
		return err
	}
	_, _, err := s.text.ReadResponse(250)
	return err
}

func (s *smtpSession) Rcpt(to string) error {
	if err := s.text.PrintfLine("RCPT TO:<%s>", to); err != nil {
		return err
	}
	_, _, err := s.text.ReadResponse(25) // 250 or 251
	return err
}

func (s *smtpSession) Data() (io.WriteCloser, error) {
	if err := s.text.PrintfLine("DATA"); err != nil {
		return nil, err
	}
	if _, _, err := s.text.ReadResponse(354); err != nil {
		return nil, err
	}
	return s.text.DotWriter(), nil
}

func (s *smtpSession) readFinalDataResponse() (int, string, error) {
	return s.text.ReadResponse(250)
}

func (s *smtpSession) Quit() error {
	if err := s.text.PrintfLine("QUIT"); err != nil {
		return err
	}
	_, _, err := s.text.ReadResponse(221)
	return err
}

func (s *smtpSession) Close() error {
	return s.text.Close()
}

// Task 6: SSRF Prevention - Block private IPs
func isPrivateIP(host string) bool {
	hostOnly := strings.Split(host, ":")[0]
	if hostOnly == "localhost" || hostOnly == "127.0.0.1" {
		return true
	}
	ip := net.ParseIP(hostOnly)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() {
			return true
		}
	}
	return false
}

// Task 7: Rate Limiting
type RateLimiter struct {
	limiters map[string]*time.Time
	mu       sync.RWMutex
}

func (rl *RateLimiter) Allow(ip string, rps float64) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	lastReq, exists := rl.limiters[ip]
	if !exists {
		rl.limiters[ip] = &now
		return true
	}
	timeSinceLastReq := now.Sub(*lastReq).Seconds()
	minInterval := 1.0 / rps
	if timeSinceLastReq >= minInterval {
		rl.limiters[ip] = &now
		return true
	}
	return false
}

// Task 8: Concurrent Request Limit
type Semaphore chan struct{}

func NewSemaphore(n int) Semaphore {
	return make(Semaphore, n)
}

func (s Semaphore) Acquire() bool {
	select {
	case s <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s Semaphore) Release() {
	<-s
}

// Task 10: Structured Logging
type RequestLogger struct {
	method    string
	path      string
	remoteIP  string
	startTime time.Time
}

func (rl *RequestLogger) Log(statusCode int, err error) {
	duration := time.Since(rl.startTime)
	if err != nil {
		log.Printf("[%s] %s %s %d %dms err=%v",
			rl.remoteIP, rl.method, rl.path,
			statusCode, duration.Milliseconds(), err)
	} else {
		log.Printf("[%s] %s %s %d %dms",
			rl.remoteIP, rl.method, rl.path, statusCode, duration.Milliseconds())
	}
	if globalTelemetry != nil {
		globalTelemetry.emitLog(context.Background(), rl.method, rl.path, rl.remoteIP, statusCode, duration, err)
	}
}

// Task 12: Error Response Structure
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

// JSONPayload is the request format sent by the Cloudflare email worker.
type JSONPayload struct {
	Raw         string            `json:"raw"`
	Envelope    Envelope          `json:"envelope"`
	Headers     MessageHeaders    `json:"headers"`
	ClientIP    string            `json:"client_ip"`
	EHLO        string            `json:"ehlo"`
	AuthResults AuthResults       `json:"auth_results"`
	SpamScore   string            `json:"spam_score"`
}

type Envelope struct {
	From string `json:"from"`
	To   StringOrStringSlice `json:"to"`
}

// StringOrStringSlice accepts a JSON value that may be either a single string
// or an array of strings. This is needed because upstream workers may send
// envelope.to as either "a@b.c" or ["a@b.c"].
type StringOrStringSlice []string

func (s *StringOrStringSlice) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if data[0] == '[' {
		var arr []string
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		*s = arr
		return nil
	}
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}
	if str != "" {
		*s = []string{str}
	}
	return nil
}

type MessageHeaders struct {
	MessageID string `json:"message_id"`
	Date      string `json:"date"`
	Subject   string `json:"subject"`
	From      string `json:"from"`
	To        string `json:"to"`
}

type AuthResults struct {
	SPF  string `json:"spf"`
	DKIM string `json:"dkim"`
}

func sendErrorResponse(w http.ResponseWriter, statusCode int, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	resp := ErrorResponse{Error: message, Code: errorCode}
	json.NewEncoder(w).Encode(resp)
}

func sendErrorResponseWithDetails(w http.ResponseWriter, statusCode int, errorCode, message, details string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	resp := ErrorResponse{Error: message, Code: errorCode, Details: details}
	json.NewEncoder(w).Encode(resp)
}

func getClientIP(r *http.Request) string {
	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP = strings.Split(strings.TrimSpace(xff), ",")[0]
	}
	return clientIP
}

// isUsableClientIP reports whether an IP address is suitable for use as the
// original client IP. Link-local, loopback, and unspecified addresses are
// rejected because they cannot be used in PROXY Protocol headers or for
// meaningful spam filtering.
func isUsableClientIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return false
	}
	return true
}

// extractClientIP returns the original client IP provided by an upstream proxy.
// It prefers explicit FormData fields (client_ip, sender_ip) or the JSON
// payload's client_ip, then Cloudflare-specific headers, then X-Forwarded-For,
// and finally the connection's remote address. Invalid/local-only IPs are skipped.
func extractClientIP(r *http.Request, payload JSONPayload) string {
	candidates := []string{
		payload.ClientIP,
		r.FormValue("client_ip"),
		r.FormValue("sender_ip"),
		r.Header.Get("CF-Connecting-IP"),
		r.Header.Get("X-Cloudflare-Client-IP"),
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for _, part := range parts {
			candidates = append(candidates, strings.TrimSpace(part))
		}
	}

	for i, candidate := range candidates {
		ip := strings.TrimSpace(candidate)
		if ip == "" {
			continue
		}
		if isUsableClientIP(ip) {
			log.Printf("client_ip selected candidate %d: %s", i, ip)
			return ip
		}
		log.Printf("client_ip rejected candidate %d (%s): unusable address", i, ip)
	}

	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host != "" && isUsableClientIP(host) {
		log.Printf("client_ip fallback to RemoteAddr host: %s", host)
		return host
	}
	if isUsableClientIP(r.RemoteAddr) {
		log.Printf("client_ip fallback to RemoteAddr: %s", r.RemoteAddr)
		return r.RemoteAddr
	}
	log.Printf("client_ip: no usable address found (RemoteAddr=%s)", r.RemoteAddr)
	return ""
}

// Task 10: Metrics collection for observability
type Metrics struct {
	requestCount      int64
	requestErrors     int64
	requestLatencyMs  int64
	rateLimitExceeded int64
	tooBusy           int64
	payloadTooLarge   int64
	mu                sync.RWMutex
}

type telemetrySink struct {
	requestCounter      otelMetric.Int64Counter
	errorCounter        otelMetric.Int64Counter
	latencyHistogram    otelMetric.Int64Histogram
	logger              otelLog.Logger
}

var globalTelemetry *telemetrySink

func (ts *telemetrySink) emitLog(ctx context.Context, method, path, remoteIP string, statusCode int, duration time.Duration, err error) {
	if ts == nil || ts.logger == nil {
		return
	}
	record := otelLog.Record{}
	record.SetBody(otelLog.StringValue(fmt.Sprintf("%s %s from=%s status=%d duration_ms=%d", method, path, remoteIP, statusCode, duration.Milliseconds())))
	if err != nil {
		record.AddAttributes(otelLog.String("error", err.Error()))
	}
	ts.logger.Emit(ctx, record)
}

func (m *Metrics) IncrementRequest() {
	atomic.AddInt64(&m.requestCount, 1)
	if globalTelemetry != nil {
		globalTelemetry.requestCounter.Add(context.Background(), 1)
	}
}
func (m *Metrics) IncrementError() {
	atomic.AddInt64(&m.requestErrors, 1)
	if globalTelemetry != nil {
		globalTelemetry.errorCounter.Add(context.Background(), 1)
	}
}
func (m *Metrics) IncrementRateLimit()        { atomic.AddInt64(&m.rateLimitExceeded, 1) }
func (m *Metrics) IncrementTooBusy()          { atomic.AddInt64(&m.tooBusy, 1) }
func (m *Metrics) IncrementPayloadTooLarge()  { atomic.AddInt64(&m.payloadTooLarge, 1) }
func (m *Metrics) AddLatency(ms int64) {
	atomic.AddInt64(&m.requestLatencyMs, ms)
	if globalTelemetry != nil {
		globalTelemetry.latencyHistogram.Record(context.Background(), ms)
	}
}
func (m *Metrics) GetStats() map[string]int64 {
	return map[string]int64{
		"total_requests":      atomic.LoadInt64(&m.requestCount),
		"total_errors":        atomic.LoadInt64(&m.requestErrors),
		"rate_limit_exceeded": atomic.LoadInt64(&m.rateLimitExceeded),
		"too_busy":            atomic.LoadInt64(&m.tooBusy),
		"payload_too_large":   atomic.LoadInt64(&m.payloadTooLarge),
		"total_latency_ms":    atomic.LoadInt64(&m.requestLatencyMs),
	}
}

func resolveCollectorEndpoint() string {
	if endpoint := strings.TrimSpace(os.Getenv("OTEL_COLLECTOR_ENDPOINT")); endpoint != "" {
		return endpoint
	}
	return strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
}

func initTelemetry() (func(context.Context) error, error) {
	endpoint := resolveCollectorEndpoint()
	if endpoint == "" {
		return func(context.Context) error { return nil }, nil
	}

	parsedURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	hostPort := parsedURL.Host
	if hostPort == "" {
		hostPort = endpoint
	}
	if parsedURL.Scheme == "http" {
		hostPort = strings.TrimPrefix(hostPort, "http://")
	} else if parsedURL.Scheme == "https" {
		hostPort = strings.TrimPrefix(hostPort, "https://")
	}

	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName("tunnelmail"),
			semconv.ServiceVersion("dev"),
		),
	)
	if err != nil {
		return nil, err
	}

	metricExporter, err := otlpmetrichttp.New(context.Background(), otlpmetrichttp.WithEndpoint(hostPort))
	if err != nil {
		return nil, err
	}

	metricReader := metricsdk.NewPeriodicReader(metricExporter)
	meterProvider := metricsdk.NewMeterProvider(
		metricsdk.WithResource(res),
		metricsdk.WithReader(metricReader),
	)
	otel.SetMeterProvider(meterProvider)

	traceExporter, err := otlptracehttp.New(context.Background(), otlptracehttp.WithEndpoint(hostPort))
	if err != nil {
		return nil, err
	}

	traceProvider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(traceProvider)

	logExporter, err := otlploghttp.New(context.Background(), otlploghttp.WithEndpoint(hostPort))
	if err != nil {
		return nil, err
	}

	logProcessor := logsdk.NewSimpleProcessor(logExporter)
	loggerProvider := logsdk.NewLoggerProvider(
		logsdk.WithResource(res),
		logsdk.WithProcessor(logProcessor),
	)
	otelGlobal.SetLoggerProvider(loggerProvider)

	meter := otel.Meter("tunnelmail")
	requestCounter, err := meter.Int64Counter("tunnelmail.requests")
	if err != nil {
		return nil, err
	}
	errorCounter, err := meter.Int64Counter("tunnelmail.errors")
	if err != nil {
		return nil, err
	}
	latencyHistogram, err := meter.Int64Histogram("tunnelmail.request_latency_ms")
	if err != nil {
		return nil, err
	}
	logger := loggerProvider.Logger("tunnelmail")
	globalTelemetry = &telemetrySink{requestCounter: requestCounter, errorCounter: errorCounter, latencyHistogram: latencyHistogram, logger: logger}

	return func(ctx context.Context) error {
		_ = meterProvider.Shutdown(ctx)
		_ = traceProvider.Shutdown(ctx)
		_ = loggerProvider.Shutdown(ctx)
		return nil
	}, nil
}

func main() {
    smtpHost := os.Getenv("SMTP_HOST")
    if smtpHost == "" {
        log.Fatal("SMTP_HOST must be set")
    }

    // Validate SMTP server is not private/internal
    if isPrivateIP(smtpHost) {
        log.Fatal("SMTP_HOST cannot be a private IP (SSRF prevention)")
    }

    // Get configuration
    smtpTimeout := time.Duration(parseEnvInt("SMTP_TIMEOUT", 30)) * time.Second
    smtpEhloHost := os.Getenv("SMTP_EHLO_HOST")
    if smtpEhloHost == "" {
        var err error
        smtpEhloHost, err = os.Hostname()
        if err != nil {
            smtpEhloHost = "tunnelmail.local"
        }
    }
    smtpEnvelopeFrom := strings.TrimSpace(os.Getenv("SMTP_ENVELOPE_FROM"))
    if smtpEnvelopeFrom != "" && !isValidEmail(smtpEnvelopeFrom) {
        log.Fatalf("SMTP_ENVELOPE_FROM is not a valid email address: %s", smtpEnvelopeFrom)
    }
    smtpUseProxyProtocol := strings.EqualFold(strings.TrimSpace(os.Getenv("SMTP_USE_PROXY_PROTOCOL")), "true")
    smtpEhloUseReverseDNS := strings.EqualFold(strings.TrimSpace(os.Getenv("SMTP_EHLO_USE_CLIENT_REVERSE_DNS")), "true")
    reverseDNSTimeout := time.Duration(parseEnvInt("SMTP_REVERSE_DNS_TIMEOUT_MS", 500)) * time.Millisecond
    log.Printf("config: SMTP_HOST=%s SMTP_EHLO_HOST=%s SMTP_USE_PROXY_PROTOCOL=%v SMTP_EHLO_USE_CLIENT_REVERSE_DNS=%v", smtpHost, smtpEhloHost, smtpUseProxyProtocol, smtpEhloUseReverseDNS)
    maxRequestSize := parseEnvInt64("MAX_REQUEST_SIZE", 100<<20) // 100MB default
    rpsLimit := float64(parseEnvInt("RATE_LIMIT_RPS", 10))
    concurrentLimit := parseEnvInt("MAX_CONCURRENT_REQUESTS", 100)

    // Initialize rate limiter
    rateLimiter := &RateLimiter{limiters: make(map[string]*time.Time)}

    // Initialize concurrent request semaphore
    semaphore := NewSemaphore(concurrentLimit)

    // Initialize metrics
    metrics := &Metrics{}

    shutdownTelemetry, err := initTelemetry()
    if err != nil {
        log.Printf("telemetry init error: %v", err)
    }
    if shutdownTelemetry != nil {
        defer func() {
            if shutdownErr := shutdownTelemetry(context.Background()); shutdownErr != nil {
                log.Printf("telemetry shutdown error: %v", shutdownErr)
            }
        }()
    }

    // Task 17: Health Check Endpoint with Metrics
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        stats := metrics.GetStats()
        response := map[string]interface{}{
            "status":  "ok",
            "metrics": stats,
        }
        json.NewEncoder(w).Encode(response)
    })

    // Main handler with all middleware
    http.HandleFunc("/inbound", func(w http.ResponseWriter, r *http.Request) {
        tracer := otel.Tracer("tunnelmail")
        ctx, span := tracer.Start(r.Context(), "inbound.request")
        defer span.End()
        r = r.WithContext(ctx)

        logger := &RequestLogger{
            method:    r.Method,
            path:      r.RequestURI,
            remoteIP:  getClientIP(r),
            startTime: time.Now(),
        }

        metrics.IncrementRequest()

        // Task 8: Concurrent limit check
        if !semaphore.Acquire() {
            metrics.IncrementTooBusy()
            metrics.IncrementError()
            span.SetStatus(codes.Error, "service too busy")
            sendErrorResponse(w, http.StatusTooManyRequests, "TOO_BUSY", "service too busy")
            logger.Log(http.StatusTooManyRequests, nil)
            metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
            return
        }
        defer semaphore.Release()

        // Task 3: Enforce request size limit
        if r.ContentLength > 0 && r.ContentLength > maxRequestSize {
            metrics.IncrementPayloadTooLarge()
            metrics.IncrementError()
            span.SetStatus(codes.Error, "request body too large")
            sendErrorResponse(w, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "request body too large")
            logger.Log(http.StatusRequestEntityTooLarge, nil)
            metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
            return
        }

        var payload JSONPayload
        var isJSON bool
        contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
        if contentType == "application/json" {
            isJSON = true
            if err := json.NewDecoder(io.LimitReader(r.Body, maxRequestSize)).Decode(&payload); err != nil {
                metrics.IncrementError()
                span.RecordError(err)
                span.SetStatus(codes.Error, "invalid json payload")
                sendErrorResponse(w, http.StatusBadRequest, "INVALID_JSON", "invalid JSON payload")
                logger.Log(http.StatusBadRequest, err)
                metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
                return
            }
        } else {
            if err := r.ParseMultipartForm(maxRequestSize); err != nil {
                metrics.IncrementError()
                span.RecordError(err)
                span.SetStatus(codes.Error, "invalid multipart form")
                sendErrorResponse(w, http.StatusBadRequest, "INVALID_MULTIPART", "invalid multipart form")
                logger.Log(http.StatusBadRequest, err)
                metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
                return
            }
        }

        // Extract the real client IP from FormData/headers/JSON payload.
        clientIP := extractClientIP(r, payload)
        logger.remoteIP = clientIP
        span.SetAttributes(
            attribute.String("client.ip", clientIP),
            attribute.String("http.method", r.Method),
            attribute.String("http.route", "/inbound"),
        )

        // Determine the EHLO hostname. The upstream worker may provide one;
        // otherwise, when enabled, prefer the reverse DNS of the original
        // client IP to avoid HELO/PTR mismatches in spam filters.
        ehloHost := smtpEhloHost
        if payload.EHLO != "" {
            ehloHost = sanitizeHeader(payload.EHLO)
            log.Printf("using EHLO hostname from upstream: %s", ehloHost)
        } else if smtpEhloUseReverseDNS && clientIP != "" {
            if ptr := reverseDNS(clientIP, reverseDNSTimeout); ptr != "" {
                log.Printf("using reverse DNS EHLO hostname for %s: %s", clientIP, ptr)
                ehloHost = ptr
            } else {
                log.Printf("reverse DNS lookup failed for %s, using EHLO hostname %s", clientIP, smtpEhloHost)
            }
        }

        // Task 7: Rate limit check
        if !rateLimiter.Allow(clientIP, rpsLimit) {
            metrics.IncrementRateLimit()
            metrics.IncrementError()
            span.SetStatus(codes.Error, "rate limit exceeded")
            sendErrorResponse(w, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", "rate limit exceeded")
            logger.Log(http.StatusTooManyRequests, nil)
            metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
            return
        }

        envelopeFrom, recipients, err := parseEnvelope(r, payload)
        if err != nil {
            metrics.IncrementError()
            span.RecordError(err)
            span.SetStatus(codes.Error, err.Error())
            sendErrorResponse(w, http.StatusBadRequest, "INVALID_ENVELOPE", err.Error())
            logger.Log(http.StatusBadRequest, err)
            metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
            return
        }

        // SMTP envelope sender may need to be a domain the relay server accepts,
        // while the original From header is preserved inside the message body.
        mailFrom := envelopeFrom
        if smtpEnvelopeFrom != "" {
            mailFrom = smtpEnvelopeFrom
        }

        rawEmail := strings.TrimSpace(r.FormValue("email"))
        if isJSON {
            rawEmail = strings.TrimSpace(payload.Raw)
        }
        messageData, err := buildMessage(r, rawEmail, envelopeFrom, recipients, clientIP, payload)
        if err != nil {
            metrics.IncrementError()
            span.RecordError(err)
            span.SetStatus(codes.Error, "failed to build message")
            log.Printf("build message error: %v", err)
            sendErrorResponse(w, http.StatusBadRequest, "BUILD_FAILED", "failed to build message")
            logger.Log(http.StatusBadRequest, err)
            metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
            return
        }

        // Task 4: Use SMTP connection with timeout and proper cleanup (Task 5)
        client, err := newSMTPSession(smtpHost, ehloHost, clientIP, smtpUseProxyProtocol, smtpTimeout)
        if err != nil {
            metrics.IncrementError()
            span.RecordError(err)
            span.SetStatus(codes.Error, "SMTP connection failed")
            log.Printf("smtp dial error: %v", err)
            sendErrorResponse(w, http.StatusBadGateway, "SMTP_CONNECT_FAILED", "SMTP connection failed")
            logger.Log(http.StatusBadGateway, err)
            metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
            return
        }
        defer client.Close()

        if err := client.Mail(mailFrom); err != nil {
            metrics.IncrementError()
            span.RecordError(err)
            span.SetStatus(codes.Error, "SMTP operation failed")
            log.Printf("smtp mail error: %v", err)
            sendErrorResponseWithDetails(w, http.StatusBadGateway, "SMTP_ERROR", "SMTP MAIL FROM failed", err.Error())
            logger.Log(http.StatusBadGateway, err)
            metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
            return
        }

        for _, recipient := range recipients {
            if err := client.Rcpt(recipient); err != nil {
                metrics.IncrementError()
                span.RecordError(err)
                span.SetStatus(codes.Error, "SMTP operation failed")
            	log.Printf("smtp rcpt error: %v", err)
            	sendErrorResponseWithDetails(w, http.StatusBadGateway, "SMTP_ERROR", fmt.Sprintf("SMTP RCPT TO <%s> failed", recipient), err.Error())
            	logger.Log(http.StatusBadGateway, err)
            	metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
            	return
            }
        }

        wc, err := client.Data()
        if err != nil {
            metrics.IncrementError()
            span.RecordError(err)
            span.SetStatus(codes.Error, "SMTP operation failed")
            log.Printf("smtp data error: %v", err)
            sendErrorResponseWithDetails(w, http.StatusBadGateway, "SMTP_ERROR", "SMTP DATA command failed", err.Error())
            logger.Log(http.StatusBadGateway, err)
            metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
            return
        }

        // Ensure the message ends with CRLF so the DATA terminator is on its own line.
        if len(messageData) > 0 && !bytes.HasSuffix(messageData, []byte("\r\n")) {
            messageData = append(messageData, '\r', '\n')
        }

        _, err = wc.Write(messageData)
        if err != nil {
            wc.Close()
            metrics.IncrementError()
            span.RecordError(err)
            span.SetStatus(codes.Error, "SMTP operation failed")
            log.Printf("smtp write error: %v", err)
            sendErrorResponseWithDetails(w, http.StatusBadGateway, "SMTP_ERROR", "SMTP DATA write failed", err.Error())
            logger.Log(http.StatusBadGateway, err)
            metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
            return
        }

        // Close the DATA writer to send the terminating "." and read the
        // server's acceptance response. This MUST happen before QUIT.
        if err := wc.Close(); err != nil {
            metrics.IncrementError()
            span.RecordError(err)
            span.SetStatus(codes.Error, "SMTP DATA acceptance failed")
            log.Printf("smtp data close error: %v", err)
            sendErrorResponseWithDetails(w, http.StatusBadGateway, "SMTP_ERROR", "SMTP server rejected message data", err.Error())
            logger.Log(http.StatusBadGateway, err)
            metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
            return
        }

        // Capture the actual SMTP response code and message (queue ID).
        smtpCode, smtpMsg, err := client.readFinalDataResponse()
        if err != nil {
            metrics.IncrementError()
            span.RecordError(err)
            span.SetStatus(codes.Error, "SMTP DATA acceptance failed")
            log.Printf("smtp data response error: %v", err)
            sendErrorResponseWithDetails(w, http.StatusBadGateway, "SMTP_ERROR", "SMTP server rejected message data", err.Error())
            logger.Log(http.StatusBadGateway, err)
            metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
            return
        }

        if err := client.Quit(); err != nil {
            // QUIT failures after successful DATA acceptance are not fatal;
            // the message has already been queued by the server.
            log.Printf("smtp quit warning: %v", err)
        }

        span.SetStatus(codes.Ok, "accepted")
        log.Printf("forwarded mail from %s to %v (%d bytes) smtp=%d %s", envelopeFrom, recipients, len(messageData), smtpCode, smtpMsg)
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "status":       "accepted",
            "smtp_code":    smtpCode,
            "smtp_message": smtpMsg,
        })
        logger.Log(http.StatusOK, nil)
        metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
    })

    port := os.Getenv("HTTP_PORT")
    if port == "" {
        port = "8080"
    }

    // Task 11: Graceful shutdown
    server := &http.Server{
        Addr:         ":" + port,
        Handler:      http.DefaultServeMux,
        ReadTimeout:  30 * time.Second,
        WriteTimeout: 30 * time.Second,
    }

    // Start server in goroutine
    go func() {
        log.Printf("listening on :%s", port)
        if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatal(err)
        }
    }()

    // Wait for interrupt signal
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
    <-sigChan

    // Graceful shutdown with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    log.Println("shutting down gracefully...")
    if err := server.Shutdown(ctx); err != nil {
        log.Printf("shutdown error: %v", err)
    }
    log.Println("server stopped")
}

func parseEnvelope(r *http.Request, payload JSONPayload) (string, []string, error) {
    from := strings.TrimSpace(payload.Envelope.From)
    if from == "" {
        from = strings.TrimSpace(r.FormValue("envelope.from"))
    }
    if from == "" {
        from = strings.TrimSpace(r.FormValue("from"))
    }
    if from == "" {
        if envRaw := strings.TrimSpace(r.FormValue("envelope")); envRaw != "" {
            var env struct {
                From string `json:"from"`
            }
            if err := json.Unmarshal([]byte(envRaw), &env); err == nil {
                from = strings.TrimSpace(env.From)
            }
        }
    }

    if from == "" {
        return "", nil, errors.New("missing envelope.from or from")
    }

    // Task 2: Validate sender email address
    if !isValidEmail(from) {
        return "", nil, errors.New("invalid from email address")
    }

    var recipients []string
    if len(payload.Envelope.To) > 0 {
        recipients = payload.Envelope.To
    }
    if raw := strings.TrimSpace(r.FormValue("envelope.to")); raw != "" {
        recipients = parseRecipients(raw)
    }
    if len(recipients) == 0 {
        if envRaw := strings.TrimSpace(r.FormValue("envelope")); envRaw != "" {
            var env struct {
                To interface{} `json:"to"`
            }
            if err := json.Unmarshal([]byte(envRaw), &env); err == nil {
                recipients = collectStrings(env.To)
            }
        }
    }
    if len(recipients) == 0 {
        recipients = parseRecipients(strings.TrimSpace(r.FormValue("to")))
    }

    if len(recipients) == 0 {
        return "", nil, errors.New("missing envelope.to or to")
    }

    // Task 2: Validate all recipient email addresses
    for _, recipient := range recipients {
        if !isValidEmail(recipient) {
            return "", nil, errors.New("invalid recipient email address: " + recipient)
        }
    }

    return from, recipients, nil
}

func parseRecipients(raw string) []string {
    raw = strings.TrimSpace(raw)
    if raw == "" {
        return nil
    }

    if strings.HasPrefix(raw, "{") || strings.HasPrefix(raw, "[") {
        var parsed interface{}
        if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
            result := collectStrings(parsed)
            if len(result) > 0 {
                return result
            }
        }
    }

    parts := strings.Split(raw, ",")
    var recipients []string
    for _, part := range parts {
        if addr := strings.TrimSpace(part); addr != "" {
            recipients = append(recipients, addr)
        }
    }
    return recipients
}

func collectStrings(value interface{}) []string {
    switch v := value.(type) {
    case string:
        if s := strings.TrimSpace(v); s != "" {
            return []string{s}
        }
    case []interface{}:
        var result []string
        for _, item := range v {
            result = append(result, collectStrings(item)...)
        }
        return result
    case map[string]interface{}:
        var result []string
        for _, item := range v {
            result = append(result, collectStrings(item)...)
        }
        return result
    }
    return nil
}

func buildMessage(r *http.Request, rawEmail, envelopeFrom string, recipients []string, clientIP string, payload JSONPayload) ([]byte, error) {
    if rawEmail != "" {
        // RFC 5321 requires CRLF line endings in the SMTP DATA phase.
        // Normalize the raw message so bare LF does not cause rejection.
        // Also inject X-Originating-IP if the upstream proxy provided a client IP.
        normalized := normalizeCRLF(rawEmail)
        if clientIP != "" && !strings.Contains(normalized, "\nX-Originating-IP:") {
            normalized = injectHeader(normalized, "X-Originating-IP", sanitizeHeader(clientIP))
        }
        normalized = injectAuthResults(normalized, payload)
        normalized = ensureRequiredHeaders(normalized, envelopeFrom)
        return []byte(normalized), nil
    }

    headers, err := parseHeaders(r.FormValue("headers"))
    if err != nil {
        log.Printf("invalid headers: %v", err)
    }

    subject := strings.TrimSpace(r.FormValue("subject"))
    if subject == "" {
        subject = headers.Get("Subject")
    }

    from := envelopeFrom
    toHeader := strings.Join(recipients, ", ")

    text := r.FormValue("text")
    html := r.FormValue("html")

    if text == "" && html == "" {
        return nil, errors.New("missing text or html body")
    }

    attachments := gatherAttachments(r)
    body, contentType, err := buildBody(text, html, attachments)
    if err != nil {
        return nil, err
    }

    headers.Del("Content-Type")
    headers.Del("Content-Transfer-Encoding")
    headers.Del("MIME-Version")
    headers.Set("MIME-Version", "1.0")
    // Task 1: Sanitize headers to prevent CRLF injection
    headers.Set("From", sanitizeHeader(from))
    headers.Set("To", sanitizeHeader(toHeader))
    if subject != "" {
        headers.Set("Subject", sanitizeHeader(subject))
    }
    if headers.Get("Date") == "" {
        headers.Set("Date", time.Now().UTC().Format(time.RFC1123Z))
    }
    if headers.Get("Message-ID") == "" {
        headers.Set("Message-ID", fmt.Sprintf("<gateway.%d@localhost>", time.Now().UnixNano()))
    }
    if clientIP != "" && headers.Get("X-Originating-IP") == "" {
        headers.Set("X-Originating-IP", sanitizeHeader(clientIP))
    }
    if payload.AuthResults.SPF != "" && headers.Get("X-AuthResults-SPF") == "" {
        headers.Set("X-AuthResults-SPF", sanitizeHeader(payload.AuthResults.SPF))
    }
    if payload.AuthResults.DKIM != "" && headers.Get("X-AuthResults-DKIM") == "" {
        headers.Set("X-AuthResults-DKIM", sanitizeHeader(payload.AuthResults.DKIM))
    }
    if payload.SpamScore != "" && headers.Get("X-Spam-Score") == "" {
        headers.Set("X-Spam-Score", sanitizeHeader(payload.SpamScore))
    }
    headers.Set("Content-Type", contentType)

    var buffer bytes.Buffer
    for key, values := range headers {
        for _, value := range values {
            // Task 1: Sanitize all header values
            fmt.Fprintf(&buffer, "%s: %s\r\n", sanitizeHeader(key), sanitizeHeader(value))
        }
    }
    buffer.WriteString("\r\n")
    buffer.Write(body)
    return buffer.Bytes(), nil
}

func parseHeaders(raw string) (textproto.MIMEHeader, error) {
    header := make(textproto.MIMEHeader)
    raw = strings.TrimSpace(raw)
    if raw == "" {
        return header, nil
    }

    if !strings.HasSuffix(raw, "\r\n") {
        raw += "\r\n"
    }
    raw += "\r\n"

    reader := bufio.NewReader(strings.NewReader(raw))
    tp := textproto.NewReader(reader)
    return tp.ReadMIMEHeader()
}

func gatherAttachments(r *http.Request) []*multipart.FileHeader {
    if r.MultipartForm == nil {
        return nil
    }
    var attachments []*multipart.FileHeader
    for _, files := range r.MultipartForm.File {
        for _, fh := range files {
            if fh.Filename != "" {
                attachments = append(attachments, fh)
            }
        }
    }
    return attachments
}

func buildBody(text, html string, attachments []*multipart.FileHeader) ([]byte, string, error) {
    if len(attachments) == 0 {
        if text != "" && html != "" {
            boundary := randomBoundary()
            body := buildAlternativeBody(text, html, boundary)
            return []byte(body), fmt.Sprintf(`multipart/alternative; boundary=%q`, boundary), nil
        }
        if html != "" {
            return []byte(html), `text/html; charset=utf-8`, nil
        }
        return []byte(text), `text/plain; charset=utf-8`, nil
    }

    var buffer bytes.Buffer
    writer := multipart.NewWriter(&buffer)
    boundary := writer.Boundary()

    partHeaders := make(textproto.MIMEHeader)
    if text != "" && html != "" {
        altBoundary := randomBoundary()
        partHeaders.Set("Content-Type", fmt.Sprintf(`multipart/alternative; boundary=%q`, altBoundary))
        part, err := writer.CreatePart(partHeaders)
        if err != nil {
            return nil, "", err
        }
        if _, err := io.WriteString(part, buildAlternativeBody(text, html, altBoundary)); err != nil {
            return nil, "", err
        }
    } else if html != "" {
        partHeaders.Set("Content-Type", `text/html; charset=utf-8`)
        partHeaders.Set("Content-Transfer-Encoding", "7bit")
        part, err := writer.CreatePart(partHeaders)
        if err != nil {
            return nil, "", err
        }
        if _, err := io.WriteString(part, html); err != nil {
            return nil, "", err
        }
    } else {
        partHeaders.Set("Content-Type", `text/plain; charset=utf-8`)
        partHeaders.Set("Content-Transfer-Encoding", "7bit")
        part, err := writer.CreatePart(partHeaders)
        if err != nil {
            return nil, "", err
        }
        if _, err := io.WriteString(part, text); err != nil {
            return nil, "", err
        }
    }

    for _, attachment := range attachments {
        if err := appendAttachment(&buffer, writer, attachment); err != nil {
            return nil, "", err
        }
    }

    if err := writer.Close(); err != nil {
        return nil, "", err
    }

    return buffer.Bytes(), fmt.Sprintf(`multipart/mixed; boundary=%q`, boundary), nil
}

func buildAlternativeBody(text, html, boundary string) string {
    var builder strings.Builder
    fmt.Fprintf(&builder, "--%s\r\n", boundary)
    builder.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
    builder.WriteString(text)
    builder.WriteString("\r\n")
    fmt.Fprintf(&builder, "--%s\r\n", boundary)
    builder.WriteString("Content-Type: text/html; charset=utf-8\r\n\r\n")
    builder.WriteString(html)
    builder.WriteString("\r\n")
    fmt.Fprintf(&builder, "--%s--\r\n", boundary)
    return builder.String()
}

func appendAttachment(buffer *bytes.Buffer, writer *multipart.Writer, attachment *multipart.FileHeader) error {
    file, err := attachment.Open()
    if err != nil {
        return err
    }
    defer file.Close()

    ext := filepath.Ext(attachment.Filename)
    contentType := mime.TypeByExtension(ext)
    if contentType == "" {
        contentType = "application/octet-stream"
    }

    partHeaders := make(textproto.MIMEHeader)
    partHeaders.Set("Content-Type", fmt.Sprintf(`%s; name=%q`, contentType, attachment.Filename))
    partHeaders.Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, attachment.Filename))
    partHeaders.Set("Content-Transfer-Encoding", "base64")

    part, err := writer.CreatePart(partHeaders)
    if err != nil {
        return err
    }

    encoder := base64.NewEncoder(base64.StdEncoding, part)
    if _, err := io.Copy(encoder, file); err != nil {
        encoder.Close()
        return err
    }
    return encoder.Close()
}

func randomBoundary() string {
    return fmt.Sprintf("BOUNDARY_%d", time.Now().UnixNano())
}
