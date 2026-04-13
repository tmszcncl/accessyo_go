package commands

import "testing"

func TestParseTarget(t *testing.T) {
	t.Run("plain domain", func(t *testing.T) {
		parsed := parseTarget("google.com", 443)
		assertTarget(t, parsed, "google.com", 443, "google.com:443", "https://google.com:443/", nil)
	})

	t.Run("domain with custom port", func(t *testing.T) {
		parsed := parseTarget("google.com:8443", 443)
		assertTarget(t, parsed, "google.com", 8443, "google.com:8443", "https://google.com:8443/", nil)
	})

	t.Run("http URL default port", func(t *testing.T) {
		parsed := parseTarget("http://google.com", 443)
		parsedFrom := "http://google.com"
		assertTarget(t, parsed, "google.com", 80, "google.com:80", "http://google.com:80/", &parsedFrom)
	})

	t.Run("https URL default port", func(t *testing.T) {
		parsed := parseTarget("https://google.com", 443)
		parsedFrom := "https://google.com"
		assertTarget(t, parsed, "google.com", 443, "google.com:443", "https://google.com:443/", &parsedFrom)
	})

	t.Run("https URL custom port and path", func(t *testing.T) {
		parsed := parseTarget("https://api.google.com:8443/v1", 443)
		parsedFrom := "https://api.google.com:8443/v1"
		assertTarget(t, parsed, "api.google.com", 8443, "api.google.com:8443", "https://api.google.com:8443/v1", &parsedFrom)
	})

	t.Run("api subdomain with custom port", func(t *testing.T) {
		parsed := parseTarget("api.example.com:8443", 443)
		assertTarget(t, parsed, "api.example.com", 8443, "api.example.com:8443", "https://api.example.com:8443/", nil)
	})

	t.Run("IPv4 localhost with port", func(t *testing.T) {
		parsed := parseTarget("127.0.0.1:8080", 443)
		assertTarget(t, parsed, "127.0.0.1", 8080, "127.0.0.1:8080", "https://127.0.0.1:8080/", nil)
	})

	t.Run("localhost with port", func(t *testing.T) {
		parsed := parseTarget("localhost:3000", 443)
		assertTarget(t, parsed, "localhost", 3000, "localhost:3000", "https://localhost:3000/", nil)
	})

	t.Run("invalid URL falls back to host parsing", func(t *testing.T) {
		parsed := parseTarget("https://bad url", 443)
		assertTarget(t, parsed, "https://bad url", 443, "[https://bad url]:443", "https://[https://bad url]:443/", nil)
	})
}

func assertTarget(
	t *testing.T,
	got parsedTarget,
	host string,
	port int,
	normalized string,
	httpTarget string,
	parsedFrom *string,
) {
	t.Helper()
	if got.host != host {
		t.Fatalf("expected host %q, got %q", host, got.host)
	}
	if got.port != port {
		t.Fatalf("expected port %d, got %d", port, got.port)
	}
	if got.normalizedTarget != normalized {
		t.Fatalf("expected normalized %q, got %q", normalized, got.normalizedTarget)
	}
	if got.httpTarget != httpTarget {
		t.Fatalf("expected httpTarget %q, got %q", httpTarget, got.httpTarget)
	}
	if parsedFrom == nil && got.parsedFrom != nil {
		t.Fatalf("expected parsedFrom nil, got %q", *got.parsedFrom)
	}
	if parsedFrom != nil {
		if got.parsedFrom == nil {
			t.Fatalf("expected parsedFrom %q, got nil", *parsedFrom)
		}
		if *got.parsedFrom != *parsedFrom {
			t.Fatalf("expected parsedFrom %q, got %q", *parsedFrom, *got.parsedFrom)
		}
	}
}
