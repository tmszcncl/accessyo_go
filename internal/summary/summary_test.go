package summary

import (
	"strings"
	"testing"

	"github.com/tmszcncl/accessyo_go/internal/types"
)

func TestBuild_AllOK(t *testing.T) {
	result := Build(Input{
		DNS:  okDNS(),
		TCP:  okTCP(),
		TLS:  okTLS(),
		HTTP: okHTTP(200),
	})

	if !result.AllOK {
		t.Fatalf("expected AllOK=true")
	}
	if result.Problem != nil || result.LikelyCause != nil {
		t.Fatalf("expected no problem/likelyCause when all checks pass")
	}
	if len(result.WhatYouCanDo) != 0 {
		t.Fatalf("expected no suggestions when all checks pass")
	}
}

func TestBuild_DNSFailure(t *testing.T) {
	dns := okDNS()
	dns.Ok = false
	err := "NXDOMAIN"
	code := "NXDOMAIN"
	dns.Error = &err
	dns.ErrorCode = &code

	result := Build(Input{DNS: dns, TCP: okTCP(), TLS: okTLS(), HTTP: okHTTP(200)})

	assertFalse(t, result.AllOK)
	assertContainsPtr(t, result.Problem, "cannot be resolved")
	assertContainsPtr(t, result.LikelyCause, "DNS")
}

func TestBuild_TCPFailure(t *testing.T) {
	tcp := okTCP()
	tcp.Ok = false
	err := "ECONNREFUSED"
	tcp.Error = &err

	result := Build(Input{DNS: okDNS(), TCP: tcp, TLS: nil, HTTP: nil})

	assertFalse(t, result.AllOK)
	assertContainsPtr(t, result.Problem, "cannot connect")
}

func TestBuild_TLSFailure(t *testing.T) {
	tlsResult := okTLS()
	tlsResult.Ok = false
	err := "certificate expired"
	tlsResult.Error = &err

	result := Build(Input{DNS: okDNS(), TCP: okTCP(), TLS: tlsResult, HTTP: nil})

	assertFalse(t, result.AllOK)
	assertContainsPtr(t, result.Problem, "secure connection")
}

func TestBuild_HTTP403Blocked(t *testing.T) {
	httpResult := okHTTP(403)
	httpResult.Ok = false

	result := Build(Input{DNS: okDNS(), TCP: okTCP(), TLS: okTLS(), HTTP: httpResult})

	assertFalse(t, result.AllOK)
	assertContainsPtr(t, result.Problem, "blocked")
	assertContainsPtr(t, result.LikelyCause, "CDN")
}

func TestBuild_HTTP404(t *testing.T) {
	httpResult := okHTTP(404)
	httpResult.Ok = false

	result := Build(Input{DNS: okDNS(), TCP: okTCP(), TLS: okTLS(), HTTP: httpResult})

	assertContainsPtr(t, result.Problem, "not found")
}

func TestBuild_HTTP500(t *testing.T) {
	httpResult := okHTTP(500)
	httpResult.Ok = false

	result := Build(Input{DNS: okDNS(), TCP: okTCP(), TLS: okTLS(), HTTP: httpResult})

	assertContainsPtr(t, result.Problem, "server error")
}

func TestBuild_NullTLSAndHTTP(t *testing.T) {
	result := Build(Input{
		DNS:  okDNS(),
		TCP:  okTCP(),
		TLS:  nil,
		HTTP: nil,
	})

	if !result.AllOK {
		t.Fatalf("expected AllOK=true when DNS/TCP pass and TLS/HTTP are nil")
	}
}

func okDNS() types.DnsResult {
	return types.DnsResult{
		Ok:         true,
		DurationMs: 10,
		Resolver:   "8.8.8.8",
		ARecords:   []string{"1.2.3.4"},
	}
}

func okTCP() types.TcpResult {
	return types.TcpResult{Ok: true, DurationMs: 20, Port: 443}
}

func okTLS() *types.TlsResult {
	return &types.TlsResult{Ok: true, DurationMs: 30}
}

func okHTTP(status int) *types.HttpResult {
	return &types.HttpResult{
		Ok:         true,
		DurationMs: 40,
		StatusCode: &status,
		Redirects:  []string{},
		Headers:    map[string]string{},
	}
}

func assertFalse(t *testing.T, value bool) {
	t.Helper()
	if value {
		t.Fatalf("expected false")
	}
}

func assertContainsPtr(t *testing.T, value *string, needle string) {
	t.Helper()
	if value == nil {
		t.Fatalf("expected non-nil string containing %q", needle)
	}
	if !strings.Contains(strings.ToLower(*value), strings.ToLower(needle)) {
		t.Fatalf("expected %q to contain %q", *value, needle)
	}
}
