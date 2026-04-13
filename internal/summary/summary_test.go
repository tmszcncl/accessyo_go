package summary

import (
	"strings"
	"testing"

	"github.com/tmszcncl/accessyo_go/internal/types"
)

func TestComputeStatus_Working(t *testing.T) {
	status := ComputeStatus(Input{
		DNS:  okDNS(),
		TCP:  okTCP(),
		TLS:  okTLS(),
		HTTP: okHTTP(),
	})
	if status != StatusWorking {
		t.Fatalf("expected WORKING, got %s", status)
	}
}

func TestComputeStatus_WorkingWhenIPv6Fails(t *testing.T) {
	http := okHTTP()
	http.IPv6 = &types.IpCheckResult{Ok: false, DurationMs: 8, Error: strPtr("timeout")}

	status := ComputeStatus(Input{
		DNS:  okDNS(),
		TCP:  okTCP(),
		TLS:  okTLS(),
		HTTP: http,
	})
	if status != StatusWorking {
		t.Fatalf("expected WORKING, got %s", status)
	}
}

func TestComputeStatus_DegradedWhenIPv4Unstable(t *testing.T) {
	http := okHTTP()
	http.IPv4 = &types.IpCheckResult{Ok: false, DurationMs: 120, Error: strPtr("timeout")}
	ttfb := int64(1300)
	http.TTFB = &ttfb

	status := ComputeStatus(Input{
		DNS:  okDNS(),
		TCP:  okTCP(),
		TLS:  okTLS(),
		HTTP: http,
	})
	if status != StatusDegraded {
		t.Fatalf("expected DEGRADED, got %s", status)
	}
}

func TestComputeStatus_DegradedWithLongRedirectChain(t *testing.T) {
	http := okHTTP()
	http.Redirects = []string{
		"https://a.example/",
		"https://b.example/",
		"https://c.example/",
	}

	status := ComputeStatus(Input{
		DNS:  okDNS(),
		TCP:  okTCP(),
		TLS:  okTLS(),
		HTTP: http,
	})
	if status != StatusDegraded {
		t.Fatalf("expected DEGRADED, got %s", status)
	}
}

func TestComputeStatus_FailOnDNSFailure(t *testing.T) {
	dns := okDNS()
	dns.Ok = false

	status := ComputeStatus(Input{
		DNS:  dns,
		TCP:  okTCP(),
		TLS:  okTLS(),
		HTTP: okHTTP(),
	})
	if status != StatusFail {
		t.Fatalf("expected FAIL, got %s", status)
	}
}

func TestBuild_WorkingSummary(t *testing.T) {
	result := Build(Input{
		DNS:  okDNS(),
		TCP:  okTCP(),
		TLS:  okTLS(),
		HTTP: okHTTP(),
	})
	if result.Status != StatusWorking {
		t.Fatalf("expected WORKING status")
	}
	if !result.AllOK {
		t.Fatalf("expected AllOK=true")
	}
	if len(result.Warnings) == 0 {
		t.Fatalf("expected at least one warning (missing HSTS)")
	}
	if result.Warnings[0].Title != "missing HSTS" || result.Warnings[0].Level != "warning" {
		t.Fatalf("expected warning-level missing HSTS, got %+v", result.Warnings[0])
	}
}

func TestBuild_KeepWorkingForIPv6Failure(t *testing.T) {
	http := okHTTP()
	http.IPv6 = &types.IpCheckResult{Ok: false, DurationMs: 10, Error: strPtr("timeout")}

	result := Build(Input{
		DNS:  okDNS(),
		TCP:  okTCP(),
		TLS:  okTLS(),
		HTTP: http,
	})
	if result.Status != StatusWorking {
		t.Fatalf("expected WORKING status, got %s", result.Status)
	}
	if !result.AllOK {
		t.Fatalf("expected AllOK=true")
	}
	if !hasWarningTitle(result.Warnings, "IPv6") {
		t.Fatalf("expected IPv6 warning")
	}
}

func TestBuild_AddSlowWarningWithoutDegrade(t *testing.T) {
	http := okHTTP()
	ttfb := int64(1200)
	http.TTFB = &ttfb

	result := Build(Input{
		DNS:  okDNS(),
		TCP:  okTCP(),
		TLS:  okTLS(),
		HTTP: http,
	})
	if result.Status != StatusWorking {
		t.Fatalf("expected WORKING status, got %s", result.Status)
	}
	if !hasWarningTitleContains(result.Warnings, "slow response") {
		t.Fatalf("expected slow response warning")
	}
}

func TestBuild_DegradedSummary(t *testing.T) {
	http := okHTTP()
	http.IPv4 = &types.IpCheckResult{Ok: false, DurationMs: 100, Error: strPtr("timeout")}

	result := Build(Input{
		DNS:  okDNS(),
		TCP:  okTCP(),
		TLS:  okTLS(),
		HTTP: http,
	})
	if result.Status != StatusDegraded {
		t.Fatalf("expected DEGRADED status, got %s", result.Status)
	}
	if !result.AllOK {
		t.Fatalf("expected AllOK=true for DEGRADED")
	}
	if !strings.Contains(strings.ToLower(result.Explanation), "degraded") {
		t.Fatalf("expected degraded explanation, got %q", result.Explanation)
	}
}

func TestBuild_UnusualRedirectsWarning(t *testing.T) {
	http := okHTTP()
	http.Redirects = []string{
		"https://a.example/",
		"https://b.example/",
		"https://c.example/",
	}

	result := Build(Input{
		DNS:  okDNS(),
		TCP:  okTCP(),
		TLS:  okTLS(),
		HTTP: http,
	})
	if result.Status != StatusDegraded {
		t.Fatalf("expected DEGRADED status, got %s", result.Status)
	}
	if !hasWarningTitle(result.Warnings, "long redirect chain") {
		t.Fatalf("expected long redirect chain warning")
	}
}

func TestBuild_HSTSInfoWhenRedirectChangesHostname(t *testing.T) {
	http := okHTTP()
	http.Redirects = []string{
		"https://google.com/",
		"https://www.google.com/",
	}

	result := Build(Input{
		DNS:  okDNS(),
		TCP:  okTCP(),
		TLS:  okTLS(),
		HTTP: http,
	})

	info := findWarning(result.Warnings, "HSTS not set on this hostname")
	if info == nil {
		t.Fatalf("expected HSTS info warning")
	}
	if info.Level != "info" {
		t.Fatalf("expected info level, got %q", info.Level)
	}
}

func TestBuild_DoesNotIncludePartialConnectivityWarning(t *testing.T) {
	http := okHTTP()
	http.IPv6 = &types.IpCheckResult{Ok: false, DurationMs: 12, Error: strPtr("timeout")}

	result := Build(Input{
		DNS:  okDNS(),
		TCP:  okTCP(),
		TLS:  okTLS(),
		HTTP: http,
	})

	if hasWarningTitleContains(result.Warnings, "partial connectivity") {
		t.Fatalf("partial connectivity warning should not be present")
	}
}

func TestBuild_DoesNotTreatClientVarianceAsWarning(t *testing.T) {
	http := okHTTP()
	browserDiffers := true
	browserStatus := 403
	http.BrowserDiffers = &browserDiffers
	http.BrowserStatusCode = &browserStatus

	result := Build(Input{
		DNS:  okDNS(),
		TCP:  okTCP(),
		TLS:  okTLS(),
		HTTP: http,
	})

	if result.Status != StatusWorking {
		t.Fatalf("expected WORKING status, got %s", result.Status)
	}
	if hasWarningTitleContains(result.Warnings, "response varies by client") {
		t.Fatalf("client variance should not be emitted as warning")
	}
}

func TestBuild_FailSummaryOnDNS(t *testing.T) {
	dns := okDNS()
	dns.Ok = false
	err := "NXDOMAIN"
	code := "NXDOMAIN"
	dns.Error = &err
	dns.ErrorCode = &code

	result := Build(Input{DNS: dns, TCP: nil, TLS: nil, HTTP: nil})
	if result.Status != StatusFail {
		t.Fatalf("expected FAIL status, got %s", result.Status)
	}
	if result.AllOK {
		t.Fatalf("expected AllOK=false on FAIL")
	}
	if result.Problem == nil || !strings.Contains(strings.ToLower(*result.Problem), "resolved") {
		t.Fatalf("expected DNS problem, got %+v", result.Problem)
	}
	if result.LikelyCause == nil || !strings.Contains(strings.ToLower(*result.LikelyCause), "dns") {
		t.Fatalf("expected DNS likely cause, got %+v", result.LikelyCause)
	}
}

func okDNS() types.DnsResult {
	return types.DnsResult{
		Ok:          true,
		DurationMs:  10,
		Resolver:    "8.8.8.8",
		ARecords:    []string{"1.2.3.4"},
		AaaaRecords: []string{"2a00:1450:4009:80b::200e"},
	}
}

func okTCP() *types.TcpResult {
	return &types.TcpResult{Ok: true, DurationMs: 20, Port: 443}
}

func okTLS() *types.TlsResult {
	return &types.TlsResult{Ok: true, DurationMs: 30}
}

func okHTTP() *types.HttpResult {
	status := 200
	ttfb := int64(200)
	return &types.HttpResult{
		Ok:         true,
		DurationMs: 40,
		StatusCode: &status,
		TTFB:       &ttfb,
		Redirects:  []string{},
		Headers:    map[string]string{},
		IPv4:       &types.IpCheckResult{Ok: true, DurationMs: 25},
		IPv6:       &types.IpCheckResult{Ok: true, DurationMs: 30},
	}
}

func hasWarningTitle(warnings []Warning, title string) bool {
	for _, warning := range warnings {
		if warning.Title == title {
			return true
		}
	}
	return false
}

func hasWarningTitleContains(warnings []Warning, text string) bool {
	for _, warning := range warnings {
		if strings.Contains(strings.ToLower(warning.Title), strings.ToLower(text)) {
			return true
		}
	}
	return false
}

func findWarning(warnings []Warning, title string) *Warning {
	for _, warning := range warnings {
		if warning.Title == title {
			w := warning
			return &w
		}
	}
	return nil
}
