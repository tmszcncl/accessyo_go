package commands

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/tmszcncl/accessyo_go/internal/checks"
	"github.com/tmszcncl/accessyo_go/internal/summary"
	"github.com/tmszcncl/accessyo_go/internal/types"
)

const defaultTimeoutMs = 5000

func Diagnose(host string, port int) error {
	fmt.Println()

	spinner := startSpinner("Detecting network...")
	ctx := checks.GetNetworkContext()
	spinner.Stop()

	printNetworkContext(ctx)

	fmt.Printf("  %s\n\n", bold(host))

	spinner2 := startSpinner("Running checks...")

	dnsResult := checks.CheckDNS(host, defaultTimeoutMs)
	var tcpResult *types.TcpResult
	if dnsResult.Ok {
		r := checks.CheckTCP(host, port, defaultTimeoutMs)
		tcpResult = &r
	}

	var tlsResult *types.TlsResult
	if tcpResult != nil && tcpResult.Ok {
		r := checks.CheckTLS(host, port, defaultTimeoutMs)
		tlsResult = &r
	}

	var httpResult *types.HttpResult
	if (tlsResult != nil && tlsResult.Ok) || (tlsResult == nil && tcpResult != nil && tcpResult.Ok) {
		r := checks.CheckHTTP(host, dnsResult.ARecords, dnsResult.AaaaRecords)
		httpResult = &r
	}

	spinner2.Stop()

	printDNS(dnsResult)
	fmt.Println()
	printTCP(tcpResult, !dnsResult.Ok)
	fmt.Println()
	printTLS(tlsResult)
	fmt.Println()
	printHTTP(httpResult)
	fmt.Println()
	printSummary(summary.Input{
		DNS:  dnsResult,
		TCP:  tcpResult,
		TLS:  tlsResult,
		HTTP: httpResult,
	})
	fmt.Println()

	return nil
}

func printNetworkContext(ctx types.NetworkContext) {
	line := dim(strings.Repeat("-", 40))
	fmt.Printf("  %s\n\n", bold("Your network:"))

	ip := "unknown"
	if ctx.PublicIP != nil {
		ip = *ctx.PublicIP
	}
	country := ""
	if ctx.Country != nil {
		country = dim(" (" + *ctx.Country + ")")
	}
	fmt.Printf("     %s    %s%s\n", dim("IP:"), ip, country)

	resolverLabel := ""
	if ctx.ResolverLabel != nil {
		resolverLabel = dim(" (" + *ctx.ResolverLabel + ")")
	}
	fmt.Printf("     %s   %s%s\n", dim("DNS:"), ctx.ResolverIP, resolverLabel)
	fmt.Println()
	fmt.Println(line)
	fmt.Println()
}

func printDNS(result types.DnsResult) {
	duration := dim(fmt.Sprintf("%dms", result.DurationMs))

	if !result.Ok {
		code := ""
		if result.ErrorCode != nil {
			code = " (" + *result.ErrorCode + ")"
		}
		fmt.Printf("  %s  DNS%s  %s\n\n", red("✗"), code, duration)
		fmt.Printf("     %s\n", red(orDefault(result.Error, "Unknown error")))
		if result.ErrorCode != nil && *result.ErrorCode == "TIMEOUT" {
			fmt.Printf("     %s possible DNS blocking or slow resolver\n", dim("->"))
		} else if result.ErrorCode != nil && *result.ErrorCode == "NXDOMAIN" {
			fmt.Printf("     %s check domain spelling\n", dim("->"))
		}
		return
	}

	fmt.Printf("  %s  DNS  %s  %s\n", green("✓"), duration, dim(fmt.Sprintf("(resolver: %s)", result.Resolver)))

	if len(result.ARecords) > 0 {
		fmt.Printf("     %s    %s\n", dim("A:"), strings.Join(result.ARecords, ", "))
	}
	if len(result.AaaaRecords) > 0 {
		fmt.Printf("     %s %s\n", dim("AAAA:"), strings.Join(result.AaaaRecords, ", "))
	}

	if len(result.ARecords) == 0 && len(result.AaaaRecords) > 0 {
		fmt.Printf("     %s IPv6 only - may fail on some networks\n", yellow("->"))
		return
	}

	if result.TTL != nil {
		fmt.Printf("     %s  %ds\n", dim("TTL:"), *result.TTL)
	}
	fmt.Printf("     %s resolves correctly\n", dim("->"))
}

func printTCP(result *types.TcpResult, dnsFailed bool) {
	if result == nil {
		reason := ""
		if dnsFailed {
			reason = dim(" (DNS failed)")
		}
		fmt.Printf("  %s  TCP  %s%s\n", dim("-"), dim("skipped"), reason)
		return
	}

	duration := dim(fmt.Sprintf("%dms", result.DurationMs))
	if !result.Ok {
		fmt.Printf("  %s  TCP  %s  %s\n\n", red("✗"), duration, dim(fmt.Sprintf("port %d", result.Port)))
		fmt.Printf("     %s\n", red(orDefault(result.Error, "Unknown error")))
		fmt.Printf("     %s TLS skipped (TCP failed)\n", dim("->"))
		return
	}
	fmt.Printf("  %s  TCP  %s  %s\n", green("✓"), duration, dim(fmt.Sprintf("port %d", result.Port)))
}

func printTLS(result *types.TlsResult) {
	if result == nil {
		fmt.Printf("  %s  TLS  %s\n", dim("-"), dim("skipped"))
		return
	}

	duration := dim(fmt.Sprintf("%dms", result.DurationMs))
	if !result.Ok {
		fmt.Printf("  %s  TLS  %s\n\n", red("✗"), duration)
		fmt.Printf("     %s\n", red(orDefault(result.Error, "Unknown error")))
		return
	}

	fmt.Printf("  %s  TLS  %s\n", green("✓"), duration)
	if result.Protocol != nil {
		fmt.Printf("     %s %s\n", dim("protocol:"), *result.Protocol)
	}
	if result.Cipher != nil {
		fmt.Printf("     %s   %s\n", dim("cipher:"), *result.Cipher)
	}
	if result.CertIssuer != nil || result.CertValidTo != nil {
		fmt.Printf("     %s\n", dim("cert:"))
		if result.CertIssuer != nil {
			fmt.Printf("       %s   %s\n", dim("issuer:"), *result.CertIssuer)
		}
		if result.CertValidTo != nil {
			validTo := *result.CertValidTo
			if result.CertExpired != nil && *result.CertExpired {
				validTo = red(validTo + " (EXPIRED)")
			}
			fmt.Printf("       %s %s\n", dim("valid to:"), validTo)
		}
	}
	fmt.Printf("     %s TLS handshake successful\n", dim("->"))

	if result.CertExpired != nil && *result.CertExpired {
		fmt.Printf("     %s certificate expired\n", red("->"))
	} else if result.CertDaysRemaining != nil && *result.CertDaysRemaining < 14 {
		fmt.Printf("     %s certificate expiring soon (~%d days remaining)\n", yellow("->"), *result.CertDaysRemaining)
	} else if result.CertDaysRemaining != nil {
		fmt.Printf("     %s certificate valid (~%d days remaining)\n", dim("->"), *result.CertDaysRemaining)
	}
}

func printHTTP(result *types.HttpResult) {
	if result == nil {
		fmt.Printf("  %s  HTTP  %s\n", dim("-"), dim("skipped"))
		return
	}

	duration := dim(fmt.Sprintf("%dms", result.DurationMs))
	if !result.Ok {
		block := ""
		if result.BlockedBy != nil {
			block = " (" + *result.BlockedBy + ")"
		}
		fmt.Printf("  %s  HTTP%s  %s\n\n", red("✗"), block, duration)
		if result.BlockedBy != nil && *result.BlockedBy == "Cloudflare" {
			fmt.Printf("     %s\n", red("Request blocked by Cloudflare / WAF"))
		} else if result.BlockedBy != nil && *result.BlockedBy == "server-side" {
			fmt.Printf("     %s\n", red("Request blocked (server-side 403)"))
		} else {
			status := "error"
			if result.StatusCode != nil {
				status = fmt.Sprintf("%d", *result.StatusCode)
			}
			fmt.Printf("     %s\n", red(orDefault(result.Error, "HTTP "+status)))
		}
		return
	}

	fmt.Printf("  %s  HTTP  %s\n", green("✓"), duration)
	if result.StatusCode != nil {
		fmt.Printf("     %s %d %s\n", dim("status:"), *result.StatusCode, statusLabel(*result.StatusCode))
	}
	if len(result.Redirects) > 0 {
		fmt.Printf("     %s\n", dim("redirects:"))
		for _, target := range result.Redirects[1:] {
			fmt.Printf("       %s %s\n", dim("->"), dim(target))
		}
	} else {
		fmt.Printf("     %s\n", dim("(no redirects)"))
	}

	if len(result.Headers) > 0 {
		fmt.Printf("     %s\n", dim("headers:"))
		keys := make([]string, 0, len(result.Headers))
		for key := range result.Headers {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			fmt.Printf("       %s %s\n", dim(key+":"), result.Headers[key])
		}
	}

	if result.IPv4 != nil || result.IPv6 != nil {
		fmt.Printf("     %s\n", dim("IP connectivity:"))
		if result.IPv4 != nil {
			icon := red("✗")
			text := red("FAIL")
			if result.IPv4.Ok {
				icon = green("✓")
				text = green("OK")
			}
			ms := dim(fmt.Sprintf("(%dms)", result.IPv4.DurationMs))
			fmt.Printf("       %s %s %s %s\n", dim("IPv4:"), icon, text, ms)
		}
		if result.IPv6 != nil {
			icon := red("✗")
			text := red("FAIL")
			if result.IPv6.Ok {
				icon = green("✓")
				text = green("OK")
			}
			ms := dim(fmt.Sprintf("(%dms)", result.IPv6.DurationMs))
			fmt.Printf("       %s %s %s %s\n", dim("IPv6:"), icon, text, ms)
		}
	}

	status := 0
	if result.StatusCode != nil {
		status = *result.StatusCode
	}

	if status >= 200 && status < 300 {
		fmt.Printf("     %s HTTP OK\n", dim("->"))
	} else if status >= 300 && status < 400 {
		fmt.Printf("     %s redirects detected\n", dim("->"))
	} else if status == 403 || status == 503 {
		fmt.Printf("     %s request blocked (possible CDN / WAF)\n", yellow("->"))
	} else if status == 404 {
		fmt.Printf("     %s page not found\n", yellow("->"))
	} else if status >= 400 && status < 500 {
		fmt.Printf("     %s client error - possible access restriction\n", yellow("->"))
	} else if status >= 500 {
		fmt.Printf("     %s server error\n", red("->"))
	}

	if result.CDN != nil {
		fmt.Printf("     %s served via %s %s\n", dim("->"), *result.CDN, dim("(CDN edge)"))
	}

	if result.IPv4 != nil && result.IPv4.Ok && result.IPv6 != nil && result.IPv6.Ok {
		fmt.Printf("     %s both IPv4 and IPv6 working\n", dim("->"))
	} else if result.IPv4 != nil && result.IPv4.Ok && result.IPv6 != nil && !result.IPv6.Ok {
		fmt.Printf("     %s IPv6 connectivity issue (may affect some users)\n", yellow("->"))
	}

	if result.BrowserDiffers != nil && *result.BrowserDiffers {
		statusText := "?"
		if result.BrowserStatusCode != nil {
			statusText = fmt.Sprintf("%d", *result.BrowserStatusCode)
		}
		fmt.Printf("     %s server responds differently to browsers (status: %s vs %d)\n", yellow("->"), statusText, status)
	}

	if result.DurationMs > 2000 {
		fmt.Printf("     %s slow response (%dms)\n", yellow("->"), result.DurationMs)
	}
}

func statusLabel(code int) string {
	switch code {
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found (Redirect)"
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 429:
		return "Too Many Requests"
	case 500:
		return "Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	default:
		return ""
	}
}

func printSummary(input summary.Input) {
	s := summary.Build(input)
	line := dim(strings.Repeat("-", 40))

	row := func(label string, ok *bool, extra string) {
		var icon string
		var text string
		if ok == nil {
			icon = dim("-")
			text = dim("skipped")
		} else if *ok {
			icon = green("✓")
			text = green("OK")
		} else {
			icon = red("✗")
			text = red("FAIL")
		}

		suffix := ""
		if extra != "" {
			suffix = dim(" (" + extra + ")")
		}
		fmt.Printf("  %-6s %s %s%s\n", label, icon, text, suffix)
	}

	fmt.Println(line)
	fmt.Println()
	row("DNS", boolPtr(input.DNS.Ok), "")
	if input.TCP == nil {
		row("TCP", nil, "")
	} else {
		row("TCP", boolPtr(input.TCP.Ok), "")
	}
	if input.TLS == nil {
		row("TLS", nil, "")
	} else {
		row("TLS", boolPtr(input.TLS.Ok), "")
	}
	if input.HTTP == nil {
		row("HTTP", nil, "")
	} else {
		extra := ""
		if input.HTTP.StatusCode != nil {
			extra = fmt.Sprintf("%d", *input.HTTP.StatusCode)
		}
		row("HTTP", boolPtr(input.HTTP.Ok), extra)
	}
	fmt.Println()

	if s.AllOK {
		fmt.Printf("  %s %s\n\n", green("STATUS:"), green("✓ WORKING"))
		fmt.Printf("  %s all checks passed\n", dim("->"))
		fmt.Println()
		fmt.Println(line)
		return
	}

	fmt.Printf("  %s %s\n\n", red("STATUS:"), red("✗ NOT WORKING"))

	if s.Problem != nil {
		fmt.Printf("  %s\n", bold("Problem:"))
		fmt.Printf("  %s %s\n\n", dim("->"), *s.Problem)
	}

	if s.LikelyCause != nil {
		fmt.Printf("  %s\n", bold("Likely cause:"))
		fmt.Printf("  %s %s\n\n", dim("->"), *s.LikelyCause)
	}

	if len(s.WhatYouCanDo) > 0 {
		fmt.Printf("  %s\n", bold("What you can do:"))
		for _, tip := range s.WhatYouCanDo {
			fmt.Printf("  %s %s\n", dim("->"), tip)
		}
		fmt.Println()
	}

	fmt.Println(line)
}

type spinner struct {
	stop chan struct{}
	done chan struct{}
}

func startSpinner(message string) *spinner {
	s := &spinner{
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}

	go func() {
		defer close(s.done)
		frames := []string{"|", "/", "-", `\`}
		ticker := time.NewTicker(90 * time.Millisecond)
		defer ticker.Stop()

		i := 0
		for {
			select {
			case <-s.stop:
				fmt.Print("\r\033[2K")
				return
			case <-ticker.C:
				fmt.Printf("\r  %s %s", dim(frames[i%len(frames)]), message)
				i++
			}
		}
	}()

	return s
}

func (s *spinner) Stop() {
	close(s.stop)
	<-s.done
}

func orDefault(value *string, fallback string) string {
	if value == nil || *value == "" {
		return fallback
	}
	return *value
}

func boolPtr(v bool) *bool { return &v }

func green(s string) string  { return "\033[32m" + s + "\033[0m" }
func red(s string) string    { return "\033[31m" + s + "\033[0m" }
func yellow(s string) string { return "\033[33m" + s + "\033[0m" }
func dim(s string) string    { return "\033[2m" + s + "\033[0m" }
func bold(s string) string   { return "\033[1m" + s + "\033[0m" }
