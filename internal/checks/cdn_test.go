package checks

import "testing"

func TestDetectCdnFromIPs(t *testing.T) {
	t.Run("detects Cloudflare IP from 104.16.0.0/13 range", func(t *testing.T) {
		got := DetectCdnFromIPs([]string{"104.16.0.1"})
		assertCDN(t, got, "Cloudflare")
	})

	t.Run("detects Cloudflare IP from 172.64.0.0/13 range", func(t *testing.T) {
		got := DetectCdnFromIPs([]string{"172.67.161.111"})
		assertCDN(t, got, "Cloudflare")
	})

	t.Run("detects Cloudflare IP from 188.114.96.0/20 range", func(t *testing.T) {
		got := DetectCdnFromIPs([]string{"188.114.96.1"})
		assertCDN(t, got, "Cloudflare")
	})

	t.Run("returns nil for a non-CDN IP", func(t *testing.T) {
		got := DetectCdnFromIPs([]string{"46.4.208.155"})
		if got != nil {
			t.Fatalf("expected nil, got %q", *got)
		}
	})

	t.Run("returns nil for an empty array", func(t *testing.T) {
		got := DetectCdnFromIPs([]string{})
		if got != nil {
			t.Fatalf("expected nil, got %q", *got)
		}
	})

	t.Run("detects Cloudflare when mixed with non-CDN IPs", func(t *testing.T) {
		got := DetectCdnFromIPs([]string{"1.2.3.4", "104.21.73.248"})
		assertCDN(t, got, "Cloudflare")
	})

	t.Run("skips IPv6 addresses", func(t *testing.T) {
		got := DetectCdnFromIPs([]string{"2606:4700::1"})
		if got != nil {
			t.Fatalf("expected nil, got %q", *got)
		}
	})

	t.Run("returns nil for localhost", func(t *testing.T) {
		got := DetectCdnFromIPs([]string{"127.0.0.1"})
		if got != nil {
			t.Fatalf("expected nil, got %q", *got)
		}
	})
}

func assertCDN(t *testing.T, got *string, expected string) {
	t.Helper()
	if got == nil {
		t.Fatalf("expected %q, got nil", expected)
	}
	if *got != expected {
		t.Fatalf("expected %q, got %q", expected, *got)
	}
}
