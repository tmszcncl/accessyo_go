package checks

import "testing"

func TestDetectCdn(t *testing.T) {
	t.Run("detects Cloudflare via cf-ray header", func(t *testing.T) {
		got := DetectCdn(map[string]string{"cf-ray": "123abc"})
		assertStringPtr(t, got, "Cloudflare")
	})

	t.Run("detects Cloudflare via cf-cache-status header", func(t *testing.T) {
		got := DetectCdn(map[string]string{"cf-cache-status": "HIT"})
		assertStringPtr(t, got, "Cloudflare")
	})

	t.Run("detects Cloudflare via server header", func(t *testing.T) {
		got := DetectCdn(map[string]string{"server": "cloudflare"})
		assertStringPtr(t, got, "Cloudflare")
	})

	t.Run("detects Cloudflare via server header case-insensitive", func(t *testing.T) {
		got := DetectCdn(map[string]string{"server": "Cloudflare"})
		assertStringPtr(t, got, "Cloudflare")
	})

	t.Run("returns nil for non-CDN headers", func(t *testing.T) {
		got := DetectCdn(map[string]string{"server": "nginx", "content-type": "text/html"})
		if got != nil {
			t.Fatalf("expected nil, got %q", *got)
		}
	})

	t.Run("returns nil for empty headers", func(t *testing.T) {
		got := DetectCdn(map[string]string{})
		if got != nil {
			t.Fatalf("expected nil, got %q", *got)
		}
	})
}

func TestDetectBlock(t *testing.T) {
	t.Run("returns Cloudflare for 403 with cf-ray", func(t *testing.T) {
		got := DetectBlock(403, map[string]string{"cf-ray": "123"})
		assertStringPtr(t, got, "Cloudflare")
	})

	t.Run("returns Cloudflare for 503 with cf-cache-status", func(t *testing.T) {
		got := DetectBlock(503, map[string]string{"cf-cache-status": "MISS"})
		assertStringPtr(t, got, "Cloudflare")
	})

	t.Run("returns server-side for 403 without CDN", func(t *testing.T) {
		got := DetectBlock(403, map[string]string{"server": "nginx"})
		assertStringPtr(t, got, "server-side")
	})

	t.Run("returns nil for 200 even with Cloudflare headers", func(t *testing.T) {
		got := DetectBlock(200, map[string]string{"cf-ray": "123"})
		if got != nil {
			t.Fatalf("expected nil, got %q", *got)
		}
	})

	t.Run("returns nil for 404 without CDN", func(t *testing.T) {
		got := DetectBlock(404, map[string]string{})
		if got != nil {
			t.Fatalf("expected nil, got %q", *got)
		}
	})
}

func TestResolveRedirect(t *testing.T) {
	t.Run("returns absolute URL unchanged", func(t *testing.T) {
		got := ResolveRedirect("https://example.com", "https://other.com/path")
		if got != "https://other.com/path" {
			t.Fatalf("expected absolute URL unchanged, got %q", got)
		}
	})

	t.Run("resolves relative path against base origin", func(t *testing.T) {
		got := ResolveRedirect("https://example.com/old", "/new")
		if got != "https://example.com/new" {
			t.Fatalf("expected resolved URL, got %q", got)
		}
	})
}

func assertStringPtr(t *testing.T, got *string, want string) {
	t.Helper()
	if got == nil {
		t.Fatalf("expected %q, got nil", want)
	}
	if *got != want {
		t.Fatalf("expected %q, got %q", want, *got)
	}
}
