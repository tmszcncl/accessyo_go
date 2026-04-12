package commands

import (
	"reflect"
	"regexp"
	"testing"

	"github.com/tmszcncl/accessyo_go/internal/types"
)

func TestBuildJSONOutput(t *testing.T) {
	baseDNS := types.DnsResult{
		Ok:         true,
		DurationMs: 12,
		Resolver:   "8.8.8.8",
		ARecords:   []string{"1.2.3.4"},
		TTL:        uint32Ptr(300),
	}
	baseTCP := &types.TcpResult{Ok: true, DurationMs: 30, Port: 443}
	baseTLS := &types.TlsResult{Ok: true, DurationMs: 80}
	baseHTTP := &types.HttpResult{Ok: true, DurationMs: 150, StatusCode: intPtr(200), Redirects: []string{}, Headers: map[string]string{}}

	t.Run("includes host and timestamp", func(t *testing.T) {
		out := buildJSONOutput("example.com", baseDNS, baseTCP, baseTLS, baseHTTP)
		if out.Host != "example.com" {
			t.Fatalf("expected host example.com, got %q", out.Host)
		}
		if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T`).MatchString(out.Timestamp) {
			t.Fatalf("expected RFC3339-like timestamp, got %q", out.Timestamp)
		}
	})

	t.Run("includes all check results", func(t *testing.T) {
		out := buildJSONOutput("example.com", baseDNS, baseTCP, baseTLS, baseHTTP)
		if !reflect.DeepEqual(out.Checks.DNS, baseDNS) {
			t.Fatalf("expected dns to match input")
		}
		if out.Checks.TCP != baseTCP {
			t.Fatalf("expected tcp pointer to match input")
		}
		if out.Checks.TLS != baseTLS {
			t.Fatalf("expected tls pointer to match input")
		}
		if out.Checks.HTTP != baseHTTP {
			t.Fatalf("expected http pointer to match input")
		}
	})

	t.Run("calculates totalMs as sum of all checks", func(t *testing.T) {
		out := buildJSONOutput("example.com", baseDNS, baseTCP, baseTLS, baseHTTP)
		if out.Summary.TotalMs != 272 {
			t.Fatalf("expected totalMs 272, got %d", out.Summary.TotalMs)
		}
	})

	t.Run("sets summary ok true when all checks pass", func(t *testing.T) {
		out := buildJSONOutput("example.com", baseDNS, baseTCP, baseTLS, baseHTTP)
		if !out.Summary.OK {
			t.Fatalf("expected ok true")
		}
		if out.Summary.Problem != nil {
			t.Fatalf("expected problem nil")
		}
	})

	t.Run("sets summary ok false and problem when DNS fails", func(t *testing.T) {
		failDNS := types.DnsResult{Ok: false, DurationMs: 5, Resolver: "8.8.8.8", Error: stringPtr("NXDOMAIN")}
		out := buildJSONOutput("bad.example", failDNS, nil, nil, nil)
		if out.Summary.OK {
			t.Fatalf("expected ok false")
		}
		if out.Summary.Problem == nil {
			t.Fatalf("expected problem to be present")
		}
	})

	t.Run("handles nil tcp/tls/http gracefully", func(t *testing.T) {
		out := buildJSONOutput("example.com", baseDNS, nil, nil, nil)
		if out.Checks.TCP != nil || out.Checks.TLS != nil || out.Checks.HTTP != nil {
			t.Fatalf("expected nil tcp/tls/http")
		}
		if out.Summary.TotalMs != 12 {
			t.Fatalf("expected totalMs 12, got %d", out.Summary.TotalMs)
		}
	})
}

func intPtr(v int) *int { return &v }

func uint32Ptr(v uint32) *uint32 { return &v }

func stringPtr(v string) *string { return &v }
