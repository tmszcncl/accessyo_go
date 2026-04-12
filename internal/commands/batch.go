package commands

import (
	"fmt"
	"strings"

	"github.com/tmszcncl/accessyo_go/internal/checks"
)

type batchResult struct {
	host     string
	ok       bool
	failedAt string
}

func checkOne(host string) batchResult {
	dns := checks.CheckDNS(host, defaultTimeoutMs)
	if !dns.Ok {
		return batchResult{host: host, ok: false, failedAt: "DNS"}
	}

	tcp := checks.CheckTCP(host, 443, defaultTimeoutMs)
	if !tcp.Ok {
		return batchResult{host: host, ok: false, failedAt: "TCP"}
	}

	tls := checks.CheckTLS(host, 443, defaultTimeoutMs)
	if !tls.Ok {
		return batchResult{host: host, ok: false, failedAt: "TLS"}
	}

	http := checks.CheckHTTP(host, dns.ARecords, dns.AaaaRecords)
	if !http.Ok {
		code := ""
		if http.StatusCode != nil {
			code = fmt.Sprintf(" %d", *http.StatusCode)
		}
		return batchResult{host: host, ok: false, failedAt: "HTTP" + code}
	}

	return batchResult{host: host, ok: true}
}

func Batch(hosts []string) error {
	fmt.Println()

	results := make([]batchResult, 0, len(hosts))
	for _, host := range hosts {
		spinner := startSpinner(host)
		result := checkOne(host)
		spinner.Stop()
		results = append(results, result)
	}

	maxLen := 0
	for _, result := range results {
		if len(result.host) > maxLen {
			maxLen = len(result.host)
		}
	}

	for _, result := range results {
		padded := result.host
		for len(padded) < maxLen+3 {
			padded += " "
		}

		if result.ok {
			fmt.Printf("  %s%s\n", padded, green("✓ WORKING"))
			continue
		}

		reason := ""
		if result.failedAt != "" {
			reason = dim(" (" + result.failedAt + ")")
		}
		fmt.Printf("  %s%s%s\n", padded, red("✗ NOT WORKING"), reason)
	}

	line := dim(strings.Repeat("-", 40))
	fmt.Println()
	fmt.Println(line)
	fmt.Println()

	working := 0
	for _, result := range results {
		if result.ok {
			working++
		}
	}
	failing := len(results) - working

	workingText := fmt.Sprintf("%d working", working)
	if working > 0 {
		workingText = green(workingText)
	}
	failingText := fmt.Sprintf("%d failing", failing)
	if failing > 0 {
		failingText = red(failingText)
	}
	fmt.Printf("  %s, %s\n\n", workingText, failingText)

	failures := make([]batchResult, 0)
	for _, result := range results {
		if !result.ok {
			failures = append(failures, result)
		}
	}

	if len(failures) > 0 {
		groups := map[string][]batchResult{}
		order := make([]string, 0)
		for _, result := range failures {
			key := result.failedAt
			if key == "" {
				key = "unknown"
			}
			if _, ok := groups[key]; !ok {
				order = append(order, key)
			}
			groups[key] = append(groups[key], result)
		}

		for _, key := range order {
			group := groups[key]
			displayHosts := make([]string, 0, len(group))
			for _, result := range group {
				displayHosts = append(displayHosts, result.host)
			}
			if len(group) > 0 {
				if err := diagnoseHost(group[0].host, 443, displayHosts); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
