package checks

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
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
	"strict-transport-security",
}

var hstsMaxAgePattern = regexp.MustCompile(`max-age=(\d+)`)

func CheckHTTP(host string, aRecords []string, aaaaRecords []string) types.HttpResult {
	return CheckHTTPWithTimeout(host, aRecords, aaaaRecords, httpTimeout)
}

func CheckHTTPWithTimeout(host string, aRecords []string, aaaaRecords []string, timeoutMs int) types.HttpResult {
	if timeoutMs <= 0 {
		timeoutMs = httpTimeout
	}

	target := host
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	start := time.Now()
	mainResult := followRedirects(target, []string{}, start, accessyoUA, timeoutMs)
	if mainResult.StatusCode == nil {
		return mainResult
	}

	bothFamilies := len(aRecords) > 0 && len(aaaaRecords) > 0

	var ipv4 *types.IpCheckResult
	var ipv6 *types.IpCheckResult
	if bothFamilies {
		v4 := quickCheck(target, quickCheckOptions{family: 4, userAgent: accessyoUA, timeoutMs: timeoutMs})
		v6 := quickCheck(target, quickCheckOptions{family: 6, userAgent: accessyoUA, timeoutMs: timeoutMs})
		ipv4 = &v4
		ipv6 = &v6
	}

	browserResult := followRedirects(target, []string{}, time.Now(), browserUA, timeoutMs)
	wwwCheck := CheckWwwRedirect(host, mainResult.Redirects)

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
	mainResult.WwwCheck = &wwwCheck
	if hstsValue := mainResult.Headers["strict-transport-security"]; hstsValue != "" {
		hsts := ParseHSTS(hstsValue)
		mainResult.HSTS = &hsts
	}
	return mainResult
}

func CheckWwwRedirect(host string, redirects []string) types.WwwCheckResult {
	bare := bareHost(host)

	isWww := strings.HasPrefix(bare, "www.")
	withoutWww := bare
	if isWww {
		withoutWww = strings.TrimPrefix(bare, "www.")
	}

	apexParts := strings.Split(withoutWww, ".")
	if len(apexParts) != 2 {
		return types.WwwCheckResult{Kind: "skipped"}
	}

	apex := withoutWww
	www := "www." + withoutWww

	chain := make([]string, 0, len(redirects))
	for _, u := range redirects {
		chain = append(chain, bareHost(u))
	}

	if !isWww {
		for _, h := range chain {
			if h == www {
				return types.WwwCheckResult{Kind: "apex→www"}
			}
		}
	} else {
		for _, h := range chain {
			if h == apex {
				return types.WwwCheckResult{Kind: "www→apex"}
			}
		}
	}

	counterpart := "https://" + www
	if isWww {
		counterpart = "https://" + apex
	}
	probe := quickCheck(counterpart, quickCheckOptions{})
	if !probe.Ok {
		return types.WwwCheckResult{Kind: "www-unreachable"}
	}

	return types.WwwCheckResult{Kind: "both-ok"}
}

func followRedirects(target string, chain []string, start time.Time, userAgent string, timeoutMs int) types.HttpResult {
	if timeoutMs <= 0 {
		timeoutMs = httpTimeout
	}
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

	client := newHTTPClient(0, timeoutMs)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
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
		message := formatHTTPError(err, timeoutMs)
		return types.HttpResult{
			Ok:         false,
			DurationMs: elapsedMs(start),
			Redirects:  chain,
			Headers:    map[string]string{},
			Error:      &message,
		}
	}
	defer resp.Body.Close()
	ttfb := elapsedMs(start)
	_, _ = io.Copy(io.Discard, resp.Body)

	filteredHeaders := extractHeaders(resp.Header)
	statusCode := resp.StatusCode

	if statusCode >= 300 && statusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			next := ResolveRedirect(target, location)
			return followRedirects(next, append(chain, target), start, userAgent, timeoutMs)
		}
	}

	blockedBy := DetectBlock(statusCode, filteredHeaders)
	cdn := DetectCdn(filteredHeaders)
	ok := statusCode >= 200 && statusCode < 500 && blockedBy == nil
	var ttfbPtr *int64
	if len(chain) == 0 {
		ttfbPtr = &ttfb
	}

	return types.HttpResult{
		Ok:         ok,
		DurationMs: elapsedMs(start),
		TTFB:       ttfbPtr,
		StatusCode: &statusCode,
		Redirects:  redirectsWithFinal(chain, target),
		Headers:    filteredHeaders,
		BlockedBy:  blockedBy,
		CDN:        cdn,
	}
}

func redirectsWithFinal(chain []string, finalURL string) []string {
	if len(chain) == 0 {
		return []string{}
	}
	out := append([]string{}, chain...)
	out = append(out, finalURL)
	return out
}

func newHTTPClient(family int, timeoutMs int) *http.Client {
	if timeoutMs <= 0 {
		timeoutMs = httpTimeout
	}
	dialer := &net.Dialer{Timeout: time.Duration(timeoutMs) * time.Millisecond}
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
		Timeout: time.Duration(timeoutMs) * time.Millisecond,
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

func ParseHSTS(value string) types.HstsInfo {
	lowered := strings.ToLower(value)
	maxAge := 0
	match := hstsMaxAgePattern.FindStringSubmatch(lowered)
	if len(match) >= 2 {
		if parsed, err := strconv.Atoi(match[1]); err == nil {
			maxAge = parsed
		}
	}

	return types.HstsInfo{
		Raw:               value,
		MaxAge:            maxAge,
		IncludeSubDomains: strings.Contains(lowered, "includesubdomains"),
		Preload:           strings.Contains(lowered, "preload"),
	}
}

type quickCheckOptions struct {
	family    int
	userAgent string
	timeoutMs int
}

func quickCheck(target string, options quickCheckOptions) types.IpCheckResult {
	start := time.Now()
	ms := options.timeoutMs
	if ms <= 0 {
		ms = httpTimeout
	}
	client := newHTTPClient(options.family, ms)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(ms)*time.Millisecond)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		message := err.Error()
		return types.IpCheckResult{Ok: false, DurationMs: elapsedMs(start), Error: &message}
	}
	if options.userAgent != "" {
		req.Header.Set("User-Agent", options.userAgent)
	}

	resp, err := client.Do(req)
	if err != nil {
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "timeout") || strings.Contains(message, "deadline exceeded") {
			timeout := "timeout"
			return types.IpCheckResult{Ok: false, DurationMs: elapsedMs(start), Error: &timeout}
		}
		original := err.Error()
		return types.IpCheckResult{Ok: false, DurationMs: elapsedMs(start), Error: &original}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	statusCode := resp.StatusCode
	// A response (even 4xx) means IP-level connectivity is working.
	ok := statusCode > 0 && statusCode < 500
	return types.IpCheckResult{
		Ok:         ok,
		StatusCode: &statusCode,
		DurationMs: elapsedMs(start),
	}
}

func formatHTTPError(err error, timeoutMs int) string {
	if err == nil {
		return "Unknown HTTP error"
	}
	if timeoutMs <= 0 {
		timeoutMs = httpTimeout
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
		return fmt.Sprintf("Timeout after %dms - server not responding", timeoutMs)
	default:
		return err.Error()
	}
}

func bareHost(input string) string {
	s := strings.TrimPrefix(input, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	return s
}
