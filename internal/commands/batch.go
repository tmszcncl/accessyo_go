package commands

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/tmszcncl/accessyo_go/internal/checks"
)

type batchResult struct {
	host     string
	ok       bool
	failedAt string
	warnings []string
}

func checkOne(host string) batchResult {
	dns := checks.CheckDNS(host, defaultTimeoutMs)
	if !dns.Ok {
		return batchResult{host: host, ok: false, failedAt: "DNS", warnings: []string{}}
	}

	tcp := checks.CheckTCP(host, 443, defaultTimeoutMs)
	if !tcp.Ok {
		return batchResult{host: host, ok: false, failedAt: "TCP", warnings: []string{}}
	}

	tls := checks.CheckTLS(host, 443, defaultTimeoutMs)
	if !tls.Ok {
		return batchResult{host: host, ok: false, failedAt: "TLS", warnings: []string{}}
	}

	http := checks.CheckHTTP(host, dns.ARecords, dns.AaaaRecords)
	if !http.Ok {
		code := ""
		if http.StatusCode != nil {
			code = fmt.Sprintf(" %d", *http.StatusCode)
		}
		return batchResult{host: host, ok: false, failedAt: "HTTP" + code, warnings: []string{}}
	}

	warnings := make([]string, 0)
	if http.HSTS == nil {
		warnings = append(warnings, "HSTS")
	} else if http.HSTS.MaxAge < 180*86400 {
		days := http.HSTS.MaxAge / 86400
		warnings = append(warnings, fmt.Sprintf("HSTS short (%dd)", days))
	}
	if tls.CertDaysRemaining != nil && *tls.CertDaysRemaining < 30 {
		warnings = append(warnings, fmt.Sprintf("cert %dd", *tls.CertDaysRemaining))
	}
	if http.IPv6 != nil && !http.IPv6.Ok {
		warnings = append(warnings, "IPv6")
	}
	if http.DurationMs > 2000 {
		warnings = append(warnings, fmt.Sprintf("slow %dms", http.DurationMs))
	}

	return batchResult{host: host, ok: true, warnings: warnings}
}

func Batch(hosts []string) error {
	fmt.Println()

	maxLen := 0
	for _, host := range hosts {
		if len(host) > maxLen {
			maxLen = len(host)
		}
	}

	resultText := func(r batchResult) string {
		status := ""
		if r.ok {
			status = green("✓ WORKING")
		} else {
			reason := ""
			if r.failedAt != "" {
				reason = dim(" (" + r.failedAt + ")")
			}
			status = red("✗ NOT WORKING") + reason
		}

		if len(r.warnings) == 0 {
			return status
		}
		warns := make([]string, 0, len(r.warnings))
		for _, warning := range r.warnings {
			warns = append(warns, yellow("⚠ "+warning))
		}
		return status + "  " + strings.Join(warns, " ")
	}

	results := make([]batchResult, len(hosts))
	isTTY := isTerminal()

	if isTTY {
		for _, host := range hosts {
			fmt.Printf("  %s%s%s\n", padRight(host, maxLen+3), dim("·"), dim(" · ·"))
		}

		var mu sync.Mutex
		var wg sync.WaitGroup
		for i, host := range hosts {
			wg.Add(1)
			go func(index int, h string) {
				defer wg.Done()
				result := checkOne(h)
				results[index] = result

				mu.Lock()
				defer mu.Unlock()
				updateRow(hosts, maxLen, index, resultText(result))
			}(i, host)
		}
		wg.Wait()
	} else {
		spinner := startSpinner(fmt.Sprintf("Checking %d domains...", len(hosts)))

		var wg sync.WaitGroup
		for i, host := range hosts {
			wg.Add(1)
			go func(index int, h string) {
				defer wg.Done()
				results[index] = checkOne(h)
			}(i, host)
		}
		wg.Wait()
		spinner.Stop()

		for i, result := range results {
			label := hosts[i]
			fmt.Printf("  %s%s\n", padRight(label, maxLen+3), resultText(result))
		}
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

func updateRow(hosts []string, maxLen int, index int, text string) {
	up := len(hosts) - index
	label := hosts[index]
	fmt.Printf("\x1b[%dA\r\x1b[2K  %s%s\x1b[%dB\r", up, padRight(label, maxLen+3), text, up)
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

func isTerminal() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}
