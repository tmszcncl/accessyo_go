package summary

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/tmszcncl/accessyo_go/internal/types"
)

type Input struct {
	DNS  types.DnsResult
	TCP  *types.TcpResult
	TLS  *types.TlsResult
	HTTP *types.HttpResult
}

type Status string

const (
	StatusWorking  Status = "WORKING"
	StatusDegraded Status = "DEGRADED"
	StatusFail     Status = "FAIL"
)

type Warning struct {
	Level  string   `json:"level"`
	Title  string   `json:"title"`
	Impact []string `json:"impact"`
}

type Result struct {
	// kept for CLI exit code and JSON compatibility: true when site is reachable
	AllOK        bool
	Status       Status
	Explanation  string
	Warnings     []Warning
	Problem      *string
	LikelyCause  *string
	WhatYouCanDo []string
}

func ComputeStatus(input Input) Status {
	if detectCriticalFailure(input) != nil {
		return StatusFail
	}

	http := input.HTTP
	if http == nil {
		return StatusFail
	}

	if isIPv4Unstable(*http) || hasRepeatedRetries(*http) || isExtremelySlow(*http) {
		return StatusDegraded
	}

	return StatusWorking
}

func Build(input Input) Result {
	status := ComputeStatus(input)
	failure := detectCriticalFailure(input)
	warnings := collectWarnings(input)

	if status == StatusFail {
		problem := strPtr("critical connectivity checks failed")
		likelyCause := strPtr("network or server issue")
		whatYouCanDo := []string{"try from a different network"}
		explanation := "critical connectivity checks failed"
		if failure != nil {
			problem = &failure.problem
			likelyCause = &failure.likelyCause
			whatYouCanDo = failure.whatYouCanDo
			explanation = failure.problem
		}
		failureWarnings := make([]Warning, 0)
		if failure != nil {
			failureWarnings = append(failureWarnings, Warning{
				Level:  "warning",
				Title:  failure.problem,
				Impact: []string{failure.likelyCause},
			})
		}
		return Result{
			AllOK:        false,
			Status:       status,
			Explanation:  explanation,
			Warnings:     append(failureWarnings, warnings...),
			Problem:      problem,
			LikelyCause:  likelyCause,
			WhatYouCanDo: whatYouCanDo,
		}
	}

	if status == StatusDegraded {
		return Result{
			AllOK:        true,
			Status:       status,
			Explanation:  "site is reachable but quality is degraded",
			Warnings:     warnings,
			Problem:      nil,
			LikelyCause:  nil,
			WhatYouCanDo: []string{},
		}
	}

	return Result{
		AllOK:        true,
		Status:       status,
		Explanation:  "site is reachable",
		Warnings:     warnings,
		Problem:      nil,
		LikelyCause:  nil,
		WhatYouCanDo: []string{},
	}
}

type failureCause struct {
	problem      string
	likelyCause  string
	whatYouCanDo []string
}

func detectCriticalFailure(input Input) *failureCause {
	dns := input.DNS
	tcp := input.TCP
	tls := input.TLS
	http := input.HTTP

	if !dns.Ok || tcp == nil {
		return &failureCause{
			problem:     "Domain cannot be resolved",
			likelyCause: "DNS misconfiguration or typo in domain name",
			whatYouCanDo: []string{
				"check domain spelling",
				"try a different DNS resolver (e.g. 1.1.1.1)",
				"try from a different network",
			},
		}
	}

	if !tcp.Ok {
		return &failureCause{
			problem:     "Cannot connect to server",
			likelyCause: "server is down or firewall is blocking the connection",
			whatYouCanDo: []string{
				"check if the service is running",
				"try from a different network",
				"disable VPN if active",
			},
		}
	}

	if tls != nil && !tls.Ok {
		return &failureCause{
			problem:     "Secure connection failed",
			likelyCause: "certificate issue or network interference (ISP / VPN)",
			whatYouCanDo: []string{
				"check certificate expiry",
				"try from a different network",
				"disable VPN if active",
			},
		}
	}

	if http == nil || !http.Ok {
		statusCode := 0
		if http != nil && http.StatusCode != nil {
			statusCode = *http.StatusCode
		}

		if (http != nil && http.BlockedBy != nil) || statusCode == 403 || statusCode == 503 {
			return &failureCause{
				problem:     "Request blocked",
				likelyCause: "CDN / firewall / WAF is blocking the request",
				whatYouCanDo: []string{
					"try from a different network (mobile vs WiFi)",
					"disable VPN if active",
					"contact the website owner",
				},
			}
		}

		if statusCode == 404 {
			return &failureCause{
				problem:     "Page not found (404)",
				likelyCause: "the URL does not exist on this server",
				whatYouCanDo: []string{
					"check the URL is correct",
					"contact the website owner",
				},
			}
		}

		if statusCode >= 500 {
			return &failureCause{
				problem:     "Server error",
				likelyCause: "the server is returning an error - likely a backend issue",
				whatYouCanDo: []string{
					"try again in a few minutes",
					"contact the website owner",
				},
			}
		}

		return &failureCause{
			problem:     "HTTP request failed",
			likelyCause: "unexpected response from server",
			whatYouCanDo: []string{
				"try from a different network",
				"contact the website owner",
			},
		}
	}

	return nil
}

func collectWarnings(input Input) []Warning {
	http := input.HTTP
	if http == nil {
		return []Warning{}
	}

	warnings := make([]Warning, 0)

	if http.IPv6 != nil && !http.IPv6.Ok {
		warnings = append(warnings, Warning{
			Level:  "warning",
			Title:  "IPv6",
			Impact: []string{"failed from your network", "may affect some users"},
		})
	}

	if http.TTFB != nil && *http.TTFB > 1000 {
		warnings = append(warnings, Warning{
			Level:  "warning",
			Title:  fmt.Sprintf("slow response (TTFB %dms)", *http.TTFB),
			Impact: []string{"response is slower than expected", "users may see delayed page loads"},
		})
	}

	if http.HSTS == nil {
		if hasRedirectToAnotherHostname(http.Redirects) {
			warnings = append(warnings, Warning{
				Level:  "info",
				Title:  "HSTS not set on this hostname",
				Impact: []string{"likely enforced on redirect target"},
			})
		} else {
			warnings = append(warnings, Warning{
				Level:  "warning",
				Title:  "missing HSTS",
				Impact: []string{"browser can be downgraded to HTTP", "transport security is weaker on first visit"},
			})
		}
	}

	if hasRepeatedRetries(*http) {
		warnings = append(warnings, Warning{
			Level:  "warning",
			Title:  "long redirect chain",
			Impact: []string{"multiple redirects before final response", "may increase page load time"},
		})
	}

	return warnings
}

func isIPv4Unstable(http types.HttpResult) bool {
	return http.IPv4 != nil && !http.IPv4.Ok
}

func hasRepeatedRetries(http types.HttpResult) bool {
	return len(http.Redirects) >= 3
}

func isExtremelySlow(http types.HttpResult) bool {
	return http.TTFB != nil && *http.TTFB > 3000
}

func hasRedirectToAnotherHostname(redirects []string) bool {
	if len(redirects) < 2 {
		return false
	}
	hosts := make(map[string]struct{})
	for _, raw := range redirects {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		hosts[strings.ToLower(parsed.Hostname())] = struct{}{}
	}
	return len(hosts) >= 2
}

func strPtr(s string) *string {
	return &s
}
