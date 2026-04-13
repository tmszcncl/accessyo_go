package commands

import (
	"reflect"
	"testing"

	"github.com/tmszcncl/accessyo_go/internal/types"
)

func TestDNSResolutionSummary(t *testing.T) {
	t.Run("returns IPv4 + IPv6 when both are present", func(t *testing.T) {
		got := dnsResolutionSummary(types.DnsResult{
			ARecords:    []string{"1.1.1.1"},
			AaaaRecords: []string{"2a00:1450:4025:804::65"},
		})
		if got != "resolved (IPv4 + IPv6)" {
			t.Fatalf("unexpected summary: %q", got)
		}
	})

	t.Run("returns IPv4 when only A exists", func(t *testing.T) {
		got := dnsResolutionSummary(types.DnsResult{
			ARecords: []string{"1.1.1.1"},
		})
		if got != "resolved (IPv4)" {
			t.Fatalf("unexpected summary: %q", got)
		}
	})

	t.Run("returns IPv6 when only AAAA exists", func(t *testing.T) {
		got := dnsResolutionSummary(types.DnsResult{
			AaaaRecords: []string{"2a00:1450:4025:804::65"},
		})
		if got != "resolved (IPv6)" {
			t.Fatalf("unexpected summary: %q", got)
		}
	})
}

func TestVisibleHTTPHeaders(t *testing.T) {
	headers := map[string]string{
		"server":                    "cloudflare",
		"cf-ray":                    "abc",
		"cache-control":             "public",
		"strict-transport-security": "max-age=123",
	}

	t.Run("returns only server in default mode", func(t *testing.T) {
		got := visibleHTTPHeaders(headers, false)
		want := []headerEntry{{Key: "server", Value: "cloudflare"}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("unexpected headers: %#v", got)
		}
	})

	t.Run("returns all headers except HSTS in debug mode", func(t *testing.T) {
		got := visibleHTTPHeaders(headers, true)
		want := []headerEntry{
			{Key: "cache-control", Value: "public"},
			{Key: "cf-ray", Value: "abc"},
			{Key: "server", Value: "cloudflare"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("unexpected headers: %#v", got)
		}
	})
}
