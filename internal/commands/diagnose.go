package commands

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tmszcncl/accessyo_go/internal/checks"
	"github.com/tmszcncl/accessyo_go/internal/types"
)

const defaultTimeoutMs = 5000

func Diagnose(host string, port int) error {
	fmt.Println()
	fmt.Printf("  %s\n\n", bold(host))

	spinner := startSpinner("Running checks...")

	var dnsResult types.DnsResult
	var tcpResult types.TcpResult

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		dnsResult = checks.CheckDNS(host, defaultTimeoutMs)
	}()
	go func() {
		defer wg.Done()
		tcpResult = checks.CheckTCP(host, port, defaultTimeoutMs)
	}()
	wg.Wait()

	var tlsResult *types.TlsResult
	if tcpResult.Ok {
		r := checks.CheckTLS(host, port, defaultTimeoutMs)
		tlsResult = &r
	}

	var httpResult *types.HttpResult
	if (tlsResult != nil && tlsResult.Ok) || (tlsResult == nil && tcpResult.Ok) {
		r := checks.CheckHTTP(host)
		httpResult = &r
	}

	spinner.Stop()

	printDNS(dnsResult)
	fmt.Println()
	printTCP(tcpResult)
	fmt.Println()
	printTLS(tlsResult)
	fmt.Println()
	printHTTP(httpResult)
	fmt.Println()

	return nil
}

func printDNS(result types.DnsResult) {
	duration := dim(fmt.Sprintf("%dms", result.DurationMs))
	resolver := dim(fmt.Sprintf("resolver: %s", result.Resolver))

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

	fmt.Printf("  %s  DNS  %s  %s\n", green("✓"), duration, resolver)

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

	ttlPart := ""
	if result.TTL != nil {
		ttlPart = fmt.Sprintf("  TTL: %ds", *result.TTL)
	}
	fmt.Printf("     %s resolves correctly%s\n", dim("->"), ttlPart)

	if result.CDN != nil {
		fmt.Printf("     %s likely behind %s %s\n", dim("->"), *result.CDN, dim("(best-effort)"))
	}
}

func printTCP(result types.TcpResult) {
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
		if result.BlockedBy != nil {
			fmt.Printf("     %s\n", red("Request blocked by CDN / WAF"))
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
		fmt.Printf("     %s %d\n", dim("status:"), *result.StatusCode)
	}
	if len(result.Redirects) > 0 {
		fmt.Printf("     %s\n", dim("redirects:"))
		for _, target := range result.Redirects {
			fmt.Printf("       %s\n", dim(target))
		}
		fmt.Printf("       %s final\n", dim("->"))
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

	status := 0
	if result.StatusCode != nil {
		status = *result.StatusCode
	}

	if status >= 200 && status < 300 {
		fmt.Printf("     %s HTTP OK\n", dim("->"))
	} else if status >= 400 && status < 500 {
		fmt.Printf("     %s client error - possible access restriction\n", yellow("->"))
	} else if status >= 500 {
		fmt.Printf("     %s server error\n", red("->"))
	}
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

func green(s string) string  { return "\033[32m" + s + "\033[0m" }
func red(s string) string    { return "\033[31m" + s + "\033[0m" }
func yellow(s string) string { return "\033[33m" + s + "\033[0m" }
func dim(s string) string    { return "\033[2m" + s + "\033[0m" }
func bold(s string) string   { return "\033[1m" + s + "\033[0m" }
