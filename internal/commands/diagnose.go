package commands

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/tmszcncl/accessyo_go/internal/checks"
	"github.com/tmszcncl/accessyo_go/internal/summary"
	"github.com/tmszcncl/accessyo_go/internal/types"
)

const defaultTimeoutMs = 5000

type renderOptions struct {
	debug      bool
	hideTiming bool
}

func Diagnose(input string, port int, timeoutMs int, jsonOutput bool, debugOutput bool) (bool, error) {
	if timeoutMs <= 0 {
		timeoutMs = defaultTimeoutMs
	}
	target := parseTarget(input, port)

	if jsonOutput {
		dns, tcp, tls, httpResult := runChecksForTarget(target, timeoutMs)
		out := buildJSONOutput(target.normalizedTarget, dns, tcp, tls, httpResult)
		encoded, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return false, err
		}
		fmt.Println(string(encoded))
		return out.Summary.OK, nil
	}

	fmt.Println()

	spinner := startSpinner("Detecting network...")
	ctx := checks.GetNetworkContext()
	spinner.Stop()

	printNetworkContext(ctx, debugOutput)
	return diagnoseHost(input, port, nil, timeoutMs, debugOutput)
}

func diagnoseHost(input string, port int, displayHosts []string, timeoutMs int, debugOutput bool) (bool, error) {
	if timeoutMs <= 0 {
		timeoutMs = defaultTimeoutMs
	}
	target := parseTarget(input, port)

	render := renderOptions{
		debug:      debugOutput,
		hideTiming: displayHosts != nil,
	}

	header := input
	if displayHosts == nil {
		header = target.normalizedTarget
	} else {
		if len(displayHosts) <= 3 {
			items := make([]string, 0, len(displayHosts))
			for _, value := range displayHosts {
				items = append(items, parseTarget(value, port).normalizedTarget)
			}
			header = strings.Join(items, ", ")
		} else {
			items := make([]string, 0, 3)
			for _, value := range displayHosts[:3] {
				items = append(items, parseTarget(value, port).normalizedTarget)
			}
			header = strings.Join(items, ", ") + dim(fmt.Sprintf(" (+%d more)", len(displayHosts)-3))
		}
	}

	fmt.Printf("  %s\n\n", bold(header))
	if displayHosts == nil && target.parsedFrom != nil {
		fmt.Printf("  %s %s\n\n", dim("->"), dim("parsed from: "+*target.parsedFrom))
	}

	spinner := startSpinner("Running checks...")

	dnsResult, tcpResult, tlsResult, httpResult := runChecksForTarget(target, timeoutMs)

	spinner.Stop()

	printDNS(dnsResult, render)
	fmt.Println()
	printTCP(tcpResult, !dnsResult.Ok, render.hideTiming)
	fmt.Println()
	printTLS(tlsResult, render)
	fmt.Println()
	printHTTP(httpResult, render)
	fmt.Println()
	printSummary(summary.Input{
		DNS:  dnsResult,
		TCP:  tcpResult,
		TLS:  tlsResult,
		HTTP: httpResult,
	})
	fmt.Println()

	result := summary.Build(summary.Input{
		DNS:  dnsResult,
		TCP:  tcpResult,
		TLS:  tlsResult,
		HTTP: httpResult,
	})
	return result.AllOK, nil
}

func runChecksForTarget(target parsedTarget, timeoutMs int) (types.DnsResult, *types.TcpResult, *types.TlsResult, *types.HttpResult) {
	dnsResult := checks.CheckDNS(target.host, timeoutMs)

	var tcpResult *types.TcpResult
	if dnsResult.Ok {
		r := checks.CheckTCP(target.host, target.port, timeoutMs)
		tcpResult = &r
	}

	var tlsResult *types.TlsResult
	if tcpResult != nil && tcpResult.Ok {
		r := checks.CheckTLS(target.host, target.port, timeoutMs)
		tlsResult = &r
	}

	var httpResult *types.HttpResult
	if (tlsResult != nil && tlsResult.Ok) || (tlsResult == nil && tcpResult != nil && tcpResult.Ok) {
		r := checks.CheckHTTPWithTimeout(target.httpTarget, target.host, dnsResult.ARecords, dnsResult.AaaaRecords, timeoutMs)
		httpResult = &r
	}

	return dnsResult, tcpResult, tlsResult, httpResult
}

func printNetworkContext(ctx types.NetworkContext, debug bool) {
	line := dim(strings.Repeat("-", 40))
	fmt.Printf("  %s\n\n", bold("Network"))

	location := formatLocation(ctx.CountryName, ctx.Country)
	if location != "" {
		printNetworkRow("Location", location)
	}
	if ctx.ISP != nil {
		printNetworkRow("ISP", *ctx.ISP)
	}
	if ctx.ASN != nil {
		printNetworkRow("ASN", *ctx.ASN)
	}
	if ctx.PublicIP != nil {
		printNetworkRow("IP", formatPublicIPForDisplay(*ctx.PublicIP, debug))
	}

	fmt.Println()
	fmt.Println(line)
	fmt.Println()
}

func printNetworkRow(label string, value string) {
	key := fmt.Sprintf("%-9s", label+":")
	fmt.Printf("  %s %s\n", dim(key), value)
}

func formatLocation(countryName, countryCode *string) string {
	if countryName != nil && countryCode != nil {
		return fmt.Sprintf("%s (%s)", *countryName, *countryCode)
	}
	if countryName != nil {
		return *countryName
	}
	if countryCode != nil {
		return *countryCode
	}
	return ""
}

func formatPublicIPForDisplay(ip string, debug bool) string {
	if debug {
		return ip
	}
	return maskPublicIP(ip)
}

func maskPublicIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			return fmt.Sprintf("%d.%d.xxx.xxx", v4[0], v4[1])
		}
	}

	if strings.Contains(ip, ":") {
		parts := strings.Split(ip, ":")
		nonEmpty := make([]string, 0, len(parts))
		for _, part := range parts {
			if part != "" {
				nonEmpty = append(nonEmpty, part)
			}
		}
		first := "xxxx"
		second := "xxxx"
		if len(nonEmpty) > 0 {
			first = nonEmpty[0]
		}
		if len(nonEmpty) > 1 {
			second = nonEmpty[1]
		}
		return first + ":" + second + ":xxxx:xxxx:xxxx:xxxx:xxxx:xxxx"
	}

	return ip
}

func dnsResolutionSummary(result types.DnsResult) string {
	hasIPv4 := len(result.ARecords) > 0
	hasIPv6 := len(result.AaaaRecords) > 0
	if hasIPv4 && hasIPv6 {
		return "resolved (IPv4 + IPv6)"
	}
	if hasIPv4 {
		return "resolved (IPv4)"
	}
	if hasIPv6 {
		return "resolved (IPv6)"
	}
	return "resolved"
}

func printDNS(result types.DnsResult, render renderOptions) {
	duration := ""
	if !render.hideTiming {
		duration = " " + dim(fmt.Sprintf("%dms", result.DurationMs))
	}

	if !result.Ok {
		code := ""
		if result.ErrorCode != nil {
			code = " (" + *result.ErrorCode + ")"
		}
		fmt.Printf("  %s  DNS%s%s\n\n", red("✗"), code, duration)
		fmt.Printf("     %s\n", red(orDefault(result.Error, "Unknown error")))
		if result.ErrorCode != nil && *result.ErrorCode == "TIMEOUT" {
			fmt.Printf("     %s possible DNS blocking or slow resolver\n", dim("->"))
		} else if result.ErrorCode != nil && *result.ErrorCode == "NXDOMAIN" {
			fmt.Printf("     %s check domain spelling\n", dim("->"))
		}
		return
	}

	if !render.debug {
		fmt.Printf("  %s  DNS%s\n", green("✓"), duration)
		fmt.Printf("     %s %s\n", dim("->"), dnsResolutionSummary(result))
		return
	}

	fmt.Printf("  %s  DNS%s  %s\n", green("✓"), duration, dim(fmt.Sprintf("(resolver: %s)", result.Resolver)))

	if len(result.ARecords) > 0 {
		fmt.Printf("     %s    %s\n", dim("A:"), strings.Join(result.ARecords, ", "))
	}
	if len(result.AaaaRecords) > 0 {
		fmt.Printf("     %s %s\n", dim("AAAA:"), strings.Join(result.AaaaRecords, ", "))
	}
	if result.CNAME != nil {
		fmt.Printf("     %s %s\n", dim("CNAME:"), *result.CNAME)
	}
	if result.ResolverComparison != nil {
		publicIPs := result.ResolverComparison.PublicIPs
		sameIPs := sameIPSet(publicIPs, result.ARecords)
		if !sameIPs {
			publicText := dim("(no response)")
			if len(publicIPs) > 0 {
				publicText = strings.Join(publicIPs, ", ")
			}
			fmt.Printf("     %s %s\n", dim("1.1.1.1:"), publicText)
		}
		if result.ResolverComparison.SplitHorizon {
			fmt.Printf("     %s split-horizon DNS detected (system DNS returns private IP)\n", yellow("->"))
		}
	}
	if result.TTL != nil {
		fmt.Printf("     %s  %ds\n", dim("TTL:"), *result.TTL)
	}
	fmt.Printf("     %s resolves correctly\n", dim("->"))
}

func printTCP(result *types.TcpResult, dnsFailed bool, hideTiming bool) {
	if result == nil {
		reason := ""
		if dnsFailed {
			reason = dim(" (DNS failed)")
		}
		fmt.Printf("  %s  TCP  %s%s\n", dim("-"), dim("skipped"), reason)
		return
	}

	duration := ""
	if !hideTiming {
		duration = " " + dim(fmt.Sprintf("%dms", result.DurationMs))
	}

	if !result.Ok {
		fmt.Printf("  %s  TCP%s  %s\n\n", red("✗"), duration, dim(fmt.Sprintf("(port %d)", result.Port)))
		fmt.Printf("     %s\n", red(orDefault(result.Error, "Unknown error")))
		fmt.Printf("     %s TLS skipped (TCP failed)\n", dim("->"))
		return
	}
	fmt.Printf("  %s  TCP%s  %s\n", green("✓"), duration, dim(fmt.Sprintf("(port %d)", result.Port)))
}

func printTLS(result *types.TlsResult, render renderOptions) {
	if result == nil {
		fmt.Printf("  %s  TLS  %s\n", dim("-"), dim("skipped"))
		return
	}

	duration := ""
	if !render.hideTiming {
		duration = " " + dim(fmt.Sprintf("%dms", result.DurationMs))
	}

	if !result.Ok {
		fmt.Printf("  %s  TLS%s\n\n", red("✗"), duration)
		fmt.Printf("     %s\n", red(orDefault(result.Error, "Unknown error")))
		return
	}

	fmt.Printf("  %s  TLS%s\n", green("✓"), duration)
	if render.debug {
		if result.Protocol != nil {
			fmt.Printf("     %s %s\n", dim("protocol:"), *result.Protocol)
		}
		if result.Cipher != nil {
			fmt.Printf("     %s   %s\n", dim("cipher:"), *result.Cipher)
		}
		if result.AlpnProtocol != nil {
			label := dim("HTTP/1.1")
			if *result.AlpnProtocol == "h2" {
				label = green("HTTP/2")
			}
			fmt.Printf("     %s    %s\n", dim("ALPN:"), label)
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
			if result.HostnameMatch != nil {
				label := red("✗ mismatch")
				if *result.HostnameMatch {
					label = green("✓ OK")
				}
				fmt.Printf("       %s %s\n", dim("hostname:"), label)
			}
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

type headerEntry struct {
	Key   string
	Value string
}

func visibleHTTPHeaders(headers map[string]string, debug bool) []headerEntry {
	if debug {
		keys := make([]string, 0, len(headers))
		for key := range headers {
			if key == "strict-transport-security" {
				continue
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)
		entries := make([]headerEntry, 0, len(keys))
		for _, key := range keys {
			entries = append(entries, headerEntry{Key: key, Value: headers[key]})
		}
		return entries
	}

	server, ok := headers["server"]
	if !ok || server == "" {
		return []headerEntry{}
	}
	return []headerEntry{{Key: "server", Value: server}}
}

func printHTTP(result *types.HttpResult, render renderOptions) {
	if result == nil {
		fmt.Printf("  %s  HTTP  %s\n", dim("-"), dim("skipped"))
		return
	}

	duration := ""
	if !render.hideTiming {
		duration = " " + dim(fmt.Sprintf("%dms", result.DurationMs))
	}

	if !result.Ok {
		block := ""
		if result.BlockedBy != nil {
			block = " (" + *result.BlockedBy + ")"
		}
		fmt.Printf("  %s  HTTP%s%s\n\n", red("✗"), block, duration)
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

	fmt.Printf("  %s  HTTP%s\n", green("✓"), duration)
	if result.StatusCode != nil {
		fmt.Printf("     %s %d %s\n", dim("status:"), *result.StatusCode, statusLabel(*result.StatusCode))
	}
	if result.TTFB != nil {
		fmt.Printf("     %s   %dms\n", dim("TTFB:"), *result.TTFB)
	}

	if len(result.Redirects) > 0 {
		fmt.Printf("     %s\n", dim("redirects:"))
		labels := make([]string, 0, len(result.Redirects))
		for _, raw := range result.Redirects {
			labels = append(labels, redirectStepLabel(raw))
		}
		fmt.Printf("       %s %s\n", dim("chain:"), dim(strings.Join(labels, " -> ")))
	} else {
		fmt.Printf("     %s\n", dim("(no redirects)"))
	}

	headerEntries := visibleHTTPHeaders(result.Headers, render.debug)
	if len(headerEntries) > 0 {
		fmt.Printf("     %s\n", dim("headers:"))
		for _, entry := range headerEntries {
			fmt.Printf("       %s %s\n", dim(entry.Key+":"), entry.Value)
		}
	}

	if result.HSTS != nil {
		days := result.HSTS.MaxAge / 86400
		ageLabel := fmt.Sprintf("%ds", result.HSTS.MaxAge)
		if days >= 1 {
			ageLabel = fmt.Sprintf("%dd", days)
		}
		tooShort := result.HSTS.MaxAge < 180*86400
		extras := ""
		if result.HSTS.IncludeSubDomains {
			extras += " - includeSubDomains"
		}
		if result.HSTS.Preload {
			extras += " - preload"
		}
		if tooShort {
			fmt.Printf("     %s    %s\n", dim("hsts:"), yellow("⚠ max-age "+ageLabel+" - increase to >= 180d"))
		} else {
			fmt.Printf("     %s    %s\n", dim("hsts:"), green("✓ max-age "+ageLabel+extras))
		}
	} else {
		fmt.Printf("     %s    %s\n", dim("hsts:"), yellow("✗ not set"))
	}

	if result.IPv4 != nil || result.IPv6 != nil {
		fmt.Printf("     %s\n", dim("IP connectivity:"))
		if result.IPv4 != nil {
			timedOut := !result.IPv4.Ok && result.IPv4.Error != nil && *result.IPv4.Error == "timeout"
			icon := red("✗")
			text := red("FAIL")
			if timedOut {
				icon = dim("-")
				text = dim("timeout (CDN rate-limit?)")
			} else if result.IPv4.Ok {
				icon = green("✓")
				text = green("OK")
			}
			ms := dim(fmt.Sprintf("(%dms)", result.IPv4.DurationMs))
			fmt.Printf("       %s %s %s %s\n", dim("IPv4:"), icon, text, ms)
		}
		if result.IPv6 != nil {
			timedOut := !result.IPv6.Ok && result.IPv6.Error != nil && *result.IPv6.Error == "timeout"
			icon := red("✗")
			text := red("FAIL")
			if timedOut {
				icon = dim("-")
				text = dim("timeout (CDN rate-limit?)")
			} else if result.IPv6.Ok {
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

	if status >= 300 && status < 400 {
		fmt.Printf("     %s redirects detected\n", dim("->"))
	} else if status == 403 || status == 503 {
		fmt.Printf("     %s request blocked (possible CDN / WAF)\n", yellow("->"))
	} else if status == 404 {
		fmt.Printf("     %s page not found\n", yellow("->"))
	} else if status >= 500 {
		fmt.Printf("     %s server error\n", red("->"))
	} else if status >= 400 {
		fmt.Printf("     %s client error - possible access restriction\n", yellow("->"))
	}

	if result.CDN != nil {
		fmt.Printf("     %s served via %s %s\n", dim("->"), *result.CDN, dim("(CDN edge)"))
	}

	if info := getClientVarianceInfo(result); info != nil {
		fmt.Printf("     %s %s\n", dim("ℹ"), info.title)
		for _, detail := range info.details {
			fmt.Printf("       %s %s\n", dim("->"), detail)
		}
	}

	if result.WwwCheck != nil {
		kind := result.WwwCheck.Kind
		if kind == "apex→www" {
			fmt.Printf("     %s redirects to www (canonical: www)\n", dim("->"))
		} else if kind == "www→apex" {
			fmt.Printf("     %s redirects to apex (canonical: non-www)\n", dim("->"))
		} else if kind == "both-ok" {
			fmt.Printf("     %s www and non-www both serve content (no canonical redirect)\n", yellow("->"))
		} else if kind == "www-unreachable" {
			fmt.Printf("     %s www version unreachable - only one variant works\n", yellow("->"))
		}
	}

}

type clientVarianceInfo struct {
	title   string
	details []string
}

func getClientVarianceInfo(result *types.HttpResult) *clientVarianceInfo {
	if result == nil || result.BrowserDiffers == nil || !*result.BrowserDiffers {
		return nil
	}
	return &clientVarianceInfo{
		title:   "response varies by client",
		details: []string{"server may treat CLI and browsers differently"},
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

func redirectStepLabel(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return rawURL
	}

	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	query := ""
	if parsed.RawQuery != "" {
		query = "?" + parsed.RawQuery
	}
	return parsed.Scheme + "://" + parsed.Host + path + query
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
	row("DNS", boolPtr(input.DNS.Ok), fmt.Sprintf("%dms", input.DNS.DurationMs))
	if input.TCP == nil {
		row("TCP", nil, "")
	} else {
		row("TCP", boolPtr(input.TCP.Ok), fmt.Sprintf("%dms", input.TCP.DurationMs))
	}
	if input.TLS == nil {
		row("TLS", nil, "")
	} else {
		row("TLS", boolPtr(input.TLS.Ok), fmt.Sprintf("%dms", input.TLS.DurationMs))
	}
	if input.HTTP == nil {
		row("HTTP", nil, "")
	} else {
		extra := fmt.Sprintf("%dms", input.HTTP.DurationMs)
		if input.HTTP.StatusCode != nil {
			extra = fmt.Sprintf("%d, %s", *input.HTTP.StatusCode, extra)
		}
		row("HTTP", boolPtr(input.HTTP.Ok), extra)
	}
	total := input.DNS.DurationMs
	if input.TCP != nil {
		total += input.TCP.DurationMs
	}
	if input.TLS != nil {
		total += input.TLS.DurationMs
	}
	if input.HTTP != nil {
		total += input.HTTP.DurationMs
	}
	fmt.Println()
	fmt.Printf("  %-6s %s\n", "Total", dim(fmt.Sprintf("%dms", total)))
	fmt.Println()

	if s.Status == summary.StatusWorking {
		fmt.Printf("  %s %s\n", green("STATUS:"), green("✓ WORKING"))
	} else if s.Status == summary.StatusDegraded {
		fmt.Printf("  %s %s\n", yellow("STATUS:"), yellow("⚠ DEGRADED"))
	} else {
		fmt.Printf("  %s %s\n", red("STATUS:"), red("✗ FAIL"))
	}
	fmt.Println()

	arrow := dim("->")
	if s.Status == summary.StatusDegraded {
		arrow = yellow("->")
	} else if s.Status == summary.StatusFail {
		arrow = red("->")
	}
	fmt.Printf("  %s %s\n", arrow, s.Explanation)

	if len(s.Warnings) > 0 {
		fmt.Println()
		fmt.Printf("  %s\n\n", bold("Warnings"))
		for _, warning := range s.Warnings {
			icon := yellow("⚠")
			if warning.Level == "info" {
				icon = dim("ℹ")
			}
			fmt.Printf("  %s %s\n\n", icon, warning.Title)
			for _, impactLine := range warning.Impact {
				fmt.Printf("    %s %s\n", dim("->"), impactLine)
			}
			fmt.Println()
		}
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

func sameIPSet(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	seen := make(map[string]int, len(a))
	for _, ip := range a {
		seen[ip]++
	}
	for _, ip := range b {
		count := seen[ip]
		if count == 0 {
			return false
		}
		seen[ip] = count - 1
	}
	return true
}

func green(s string) string  { return "\033[32m" + s + "\033[0m" }
func red(s string) string    { return "\033[31m" + s + "\033[0m" }
func yellow(s string) string { return "\033[33m" + s + "\033[0m" }
func dim(s string) string    { return "\033[2m" + s + "\033[0m" }
func bold(s string) string   { return "\033[1m" + s + "\033[0m" }
