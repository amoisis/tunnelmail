package main

import "testing"

func TestResolveCollectorEndpoint(t *testing.T) {
	t.Run("uses explicit collector endpoint", func(t *testing.T) {
		t.Setenv("OTEL_COLLECTOR_ENDPOINT", "http://collector:4318")
		t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://fallback:4318")

		if got := resolveCollectorEndpoint(); got != "http://collector:4318" {
			t.Fatalf("resolveCollectorEndpoint() = %q, want %q", got, "http://collector:4318")
		}
	})

	t.Run("falls back to otlp endpoint", func(t *testing.T) {
		t.Setenv("OTEL_COLLECTOR_ENDPOINT", "")
		t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://fallback:4318")

		if got := resolveCollectorEndpoint(); got != "http://fallback:4318" {
			t.Fatalf("resolveCollectorEndpoint() = %q, want %q", got, "http://fallback:4318")
		}
	})

	t.Run("returns empty when unset", func(t *testing.T) {
		t.Setenv("OTEL_COLLECTOR_ENDPOINT", "")
		t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")

		if got := resolveCollectorEndpoint(); got != "" {
			t.Fatalf("resolveCollectorEndpoint() = %q, want empty", got)
		}
	})
}
