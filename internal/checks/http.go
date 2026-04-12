package checks

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tmszcncl/accessyo_go/internal/types"
)

const (
	maxRedirects = 5
	httpTimeout  = 5000
	accessyoUA   = "accessyo/0.1 (+https://github.com/tmszcncl/accessyo_npx)"
	browserUA    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

var keyHeaders = []string{
	"server",
	"content-type",
	"location",
	"cf-ray",
	"cf-cache-status",
	"x-powered-by",
}

func CheckHTTP(host string, aRecords []string, aaaaRecords []string) types.HttpResult {
	target := host
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	start := time.Now()
	mainResult := followRedirects(target, []string{}, start, accessyoUA)
	if mainResult.StatusCode == nil {
		return mainResult
	}

	bothFamilies := len(aRecords) > 0 && len(aaaaRecords) > 0

	var ipv4 *types.IpCheckResult
	var ipv6 *types.IpCheckResult
	if bothFamilies {
		v4 := quickCheck(target, quickCheckOptions{family: 4})
		v6 := quickCheck(target, quickCheckOptions{family: 6})
		ipv4 = &v4
		ipv6 = &v6
	}

	browserResult := followRedirects(target, []string{}, time.Now(), browserUA)

	browserFinal := 0
	if browserResult.StatusCode != nil {
		browserFinal = *browserResult.StatusCode
	}
	mainFinal := *mainResult.StatusCode
	differs := browserFinal >= 400 && mainFinal < 400

	mainResult.IPv4 = ipv4
	mainResult.IPv6 = ipv6
	mainResult.BrowserStatusCode = browserResult.StatusCode
	mainResult.BrowserDiffers = &differs
	return mainResult
}

func followRedirects(target string, chain []string, start time.Time, userAgent string) types.HttpResult {
	if len(chain) > maxRedirects {
		message := "Too many redirects (redirect loop)"
		return types.HttpResult{
			Ok:         false,
			DurationMs: elapsedMs(start),
			Redirects:  chain,
			Headers:    map[string]string{},
			Error:      &message,
		}
	}

	client := newHTTPClient(0)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(httpTimeout)*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		message := err.Error()
		return types.HttpResult{
			Ok:         false,
			DurationMs: elapsedMs(start),
			Redirects:  chain,
			Headers:    map[string]string{},
			Error:      &message,
		}
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		message := formatHTTPError(err)
		return types.HttpResult{
			Ok:         false,
			DurationMs: elapsedMs(start),
			Redirects:  chain,
			Headers:    map[string]string{},
			Error:      &message,
		}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	filteredHeaders := extractHeaders(resp.Header)
	statusCode := resp.StatusCode

	if statusCode >= 300 && statusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			next := ResolveRedirect(target, location)
			return followRedirects(next, append(chain, target), start, userAgent)
		}
	}

	blockedBy := DetectBlock(statusCode, filteredHeaders)
	cdn := DetectCdn(filteredHeaders)
	ok := statusCode >= 200 && statusCode < 500 && blockedBy == nil

	return types.HttpResult{
		Ok:         ok,
		DurationMs: elapsedMs(start),
		StatusCode: &statusCode,
		Redirects:  chain,
		Headers:    filteredHeaders,
		BlockedBy:  blockedBy,
		CDN:        cdn,
	}
}

func newHTTPClient(family int) *http.Client {
	dialer := &net.Dialer{Timeout: time.Duration(httpTimeout) * time.Millisecond}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	if family == 4 || family == 6 {
		network := "tcp4"
		if family == 6 {
			network = "tcp6"
		}
		transport.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		}
	}

	return &http.Client{
		Timeout: time.Duration(httpTimeout) * time.Millisecond,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: transport,
	}
}

func extractHeaders(headers http.Header) map[string]string {
	result := map[string]string{}
	for _, key := range keyHeaders {
		if value := headers.Get(key); value != "" {
			result[key] = value
		}
	}
	return result
}

func ResolveRedirect(baseURL string, location string) string {
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		return location
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return location
	}
	return parsed.Scheme + "://" + parsed.Host + location
}

func DetectCdn(headers map[string]string) *string {
	server := strings.ToLower(headers["server"])
	if headers["cf-ray"] != "" || headers["cf-cache-status"] != "" || strings.Contains(server, "cloudflare") {
		return strPtr("Cloudflare")
	}
	return nil
}

func DetectBlock(status int, headers map[string]string) *string {
	cdn := DetectCdn(headers)
	if cdn != nil && (status == 403 || status == 503) {
		return cdn
	}
	if status == 403 {
		return strPtr("server-side")
	}
	return nil
}

type quickCheckOptions struct {
	family int
}

func quickCheck(target string, options quickCheckOptions) types.IpCheckResult {
	client := newHTTPClient(options.family)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(httpTimeout)*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		message := err.Error()
		return types.IpCheckResult{Ok: false, Error: &message}
	}

	resp, err := client.Do(req)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "timeout") || strings.Contains(message, "deadline exceeded") {
			timeout := "timeout"
			return types.IpCheckResult{Ok: false, Error: &timeout}
		}
		original := err.Error()
		return types.IpCheckResult{Ok: false, Error: &original}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	statusCode := resp.StatusCode
	ok := statusCode >= 200 && statusCode < 400
	return types.IpCheckResult{
		Ok:         ok,
		StatusCode: &statusCode,
	}
}

func formatHTTPError(err error) string {
	if err == nil {
		return "Unknown HTTP error"
	}

	lowered := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lowered, "connection reset"):
		return "Connection reset - possible firewall or backend issue"
	case strings.Contains(lowered, "connection refused"):
		return "Connection refused"
	case strings.Contains(lowered, "no such host"):
		return "Host not found"
	case strings.Contains(lowered, "x509"), strings.Contains(lowered, "certificate"):
		return "TLS/certificate error"
	case strings.Contains(lowered, "deadline exceeded"), strings.Contains(lowered, "timeout"):
		return "Timeout after 5000ms - server not responding"
	default:
		return err.Error()
	}
}
