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
	"net/smtp"
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

// Task 4: SMTP Connection Timeout
func dialSMTPWithTimeout(host string, timeout time.Duration) (*smtp.Client, error) {
	conn, err := net.DialTimeout("tcp", host, timeout)
	if err != nil {
		return nil, err
	}
	hostname := strings.Split(host, ":")[0]
	client, err := smtp.NewClient(conn, hostname)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return client, nil
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
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

func sendErrorResponse(w http.ResponseWriter, statusCode int, errorCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	resp := ErrorResponse{Error: message, Code: errorCode}
	json.NewEncoder(w).Encode(resp)
}

func getClientIP(r *http.Request) string {
	clientIP := strings.Split(r.RemoteAddr, ":")[0]
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP = strings.Split(strings.TrimSpace(xff), ",")[0]
	}
	return clientIP
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
        clientIP := getClientIP(r)
        tracer := otel.Tracer("tunnelmail")
        ctx, span := tracer.Start(r.Context(), "inbound.request")
        defer span.End()
        r = r.WithContext(ctx)
        span.SetAttributes(
            attribute.String("client.ip", clientIP),
            attribute.String("http.method", r.Method),
            attribute.String("http.route", "/inbound"),
        )

        logger := &RequestLogger{
            method:    r.Method,
            path:      r.RequestURI,
            remoteIP:  clientIP,
            startTime: time.Now(),
        }

        metrics.IncrementRequest()

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

        if err := r.ParseMultipartForm(maxRequestSize); err != nil {
            metrics.IncrementError()
            span.RecordError(err)
            span.SetStatus(codes.Error, "invalid multipart form")
            sendErrorResponse(w, http.StatusBadRequest, "INVALID_MULTIPART", "invalid multipart form")
            logger.Log(http.StatusBadRequest, err)
            metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
            return
        }

        envelopeFrom, recipients, err := parseEnvelope(r)
        if err != nil {
            metrics.IncrementError()
            span.RecordError(err)
            span.SetStatus(codes.Error, err.Error())
            sendErrorResponse(w, http.StatusBadRequest, "INVALID_ENVELOPE", err.Error())
            logger.Log(http.StatusBadRequest, err)
            metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
            return
        }

        rawEmail := strings.TrimSpace(r.FormValue("email"))
        messageData, err := buildMessage(r, rawEmail, envelopeFrom, recipients)
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
        client, err := dialSMTPWithTimeout(smtpHost, smtpTimeout)
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

        if err := client.Mail(envelopeFrom); err != nil {
            metrics.IncrementError()
            span.RecordError(err)
            span.SetStatus(codes.Error, "SMTP operation failed")
            log.Printf("smtp mail error: %v", err)
            sendErrorResponse(w, http.StatusBadGateway, "SMTP_ERROR", "SMTP operation failed")
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
            	sendErrorResponse(w, http.StatusBadGateway, "SMTP_ERROR", "SMTP operation failed")
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
            sendErrorResponse(w, http.StatusBadGateway, "SMTP_ERROR", "SMTP operation failed")
            logger.Log(http.StatusBadGateway, err)
            metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
            return
        }
        defer wc.Close()

        _, err = wc.Write(messageData)
        if err != nil {
            metrics.IncrementError()
            span.RecordError(err)
            span.SetStatus(codes.Error, "SMTP operation failed")
            log.Printf("smtp write error: %v", err)
            sendErrorResponse(w, http.StatusBadGateway, "SMTP_ERROR", "SMTP operation failed")
            logger.Log(http.StatusBadGateway, err)
            metrics.AddLatency(time.Since(logger.startTime).Milliseconds())
            return
        }

        if err := client.Quit(); err != nil {
            metrics.IncrementError()
            span.RecordError(err)
            span.SetStatus(codes.Error, "SMTP operation failed")
            log.Printf("smtp quit error: %v", err)
        }

        span.SetStatus(codes.Ok, "accepted")
        log.Printf("forwarded mail from %s to %v (%d bytes)", envelopeFrom, recipients, len(messageData))
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(map[string]string{"status": "accepted"})
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

func parseEnvelope(r *http.Request) (string, []string, error) {
    from := strings.TrimSpace(r.FormValue("envelope.from"))
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

func buildMessage(r *http.Request, rawEmail, envelopeFrom string, recipients []string) ([]byte, error) {
    if rawEmail != "" {
        return []byte(rawEmail), nil
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
