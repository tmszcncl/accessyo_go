package checks

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/tmszcncl/accessyo_go/internal/types"
)

const (
	maxRedirects = 5
	httpTimeout  = 5000
)

var keyHeaders = []string{
	"server",
	"content-type",
	"location",
	"cf-ray",
	"cf-cache-status",
	"x-powered-by",
}

func CheckHTTP(host string) types.HttpResult {
	target := host
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	return followRedirects(target, []string{}, time.Now())
}

func followRedirects(target string, chain []string, start time.Time) types.HttpResult {
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

	client := &http.Client{
		Timeout: time.Duration(httpTimeout) * time.Millisecond,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}

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
			next := resolveRedirect(target, location)
			return followRedirects(next, append(chain, target), start)
		}
	}

	blockedBy := detectBlock(statusCode, filteredHeaders)
	ok := statusCode >= 200 && statusCode < 500 && blockedBy == nil

	return types.HttpResult{
		Ok:         ok,
		DurationMs: elapsedMs(start),
		StatusCode: &statusCode,
		Redirects:  chain,
		Headers:    filteredHeaders,
		BlockedBy:  blockedBy,
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

func resolveRedirect(baseURL string, location string) string {
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		return location
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		return location
	}
	return parsed.Scheme + "://" + parsed.Host + location
}

func detectBlock(status int, headers map[string]string) *string {
	server := strings.ToLower(headers["server"])
	isCloudflare := headers["cf-ray"] != "" || headers["cf-cache-status"] != "" || strings.Contains(server, "cloudflare")
	if isCloudflare && (status == 403 || status == 503) {
		return strPtr("Cloudflare")
	}
	return nil
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

func sortedHeaderKeys(headers map[string]string) []string {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
