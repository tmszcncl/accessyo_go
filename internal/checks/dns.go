package checks

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tmszcncl/accessyo_go/internal/types"
)

func CheckDNS(host string, timeoutMs int) types.DnsResult {
	start := time.Now()
	resolver := getResolver()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	var aRecords []string
	var aaaaRecords []string
	var cname *string
	var aErr error
	var aaaaErr error
	var cnameErr error

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		wg.Add(3)

		go func() {
			defer wg.Done()
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
			if err != nil {
				aErr = err
				return
			}
			aRecords = dedupeIPStrings(ips)
		}()

		go func() {
			defer wg.Done()
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip6", host)
			if err != nil {
				aaaaErr = err
				return
			}
			aaaaRecords = dedupeIPStrings(ips)
		}()

		go func() {
			defer wg.Done()
			record, err := net.DefaultResolver.LookupCNAME(ctx, host)
			if err != nil {
				cnameErr = err
				return
			}
			trimmed := strings.TrimSuffix(record, ".")
			if trimmed != "" {
				cname = &trimmed
			}
		}()

		wg.Wait()
	}()

	<-done

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		errorText := "Timed out"
		errorCode := "TIMEOUT"
		return types.DnsResult{
			Ok:         false,
			DurationMs: elapsedMs(start),
			Resolver:   resolver,
			Error:      &errorText,
			ErrorCode:  &errorCode,
		}
	}

	ok := len(aRecords) > 0 || len(aaaaRecords) > 0
	if !ok {
		err := firstError(aErr, aaaaErr, cnameErr)
		message := formatDNSError(err)
		code := dnsErrorCode(err)
		return types.DnsResult{
			Ok:         false,
			DurationMs: elapsedMs(start),
			Resolver:   resolver,
			Error:      &message,
			ErrorCode:  code,
		}
	}

	allIPs := append([]string{}, aRecords...)
	allIPs = append(allIPs, aaaaRecords...)
	cdn := DetectCdnFromIPs(allIPs)
	resolverComparison := queryPublicResolver(host, aRecords, timeoutMs)

	return types.DnsResult{
		Ok:                 true,
		DurationMs:         elapsedMs(start),
		Resolver:           resolver,
		ARecords:           aRecords,
		AaaaRecords:        aaaaRecords,
		CNAME:              cname,
		TTL:                nil,
		CDN:                cdn,
		ResolverComparison: resolverComparison,
	}
}

func dedupeIPStrings(ips []net.IP) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		s := ip.String()
		if _, exists := seen[s]; exists {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return errors.New("No DNS records found")
}

func formatDNSError(err error) string {
	if err == nil {
		return "Unknown DNS error"
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return "NXDOMAIN - domain does not exist"
		}
		if dnsErr.IsTimeout {
			return "Timed out"
		}
	}

	lowered := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lowered, "no such host"):
		return "NXDOMAIN - domain does not exist"
	case strings.Contains(lowered, "timed out"), strings.Contains(lowered, "i/o timeout"):
		return "Timed out"
	case strings.Contains(lowered, "servfail"), strings.Contains(lowered, "server misbehaving"):
		return "SERVFAIL - DNS server failure"
	case strings.Contains(lowered, "no data"):
		return "No records found"
	case strings.Contains(lowered, "connection refused"):
		return "DNS resolver unreachable"
	default:
		return err.Error()
	}
}

func dnsErrorCode(err error) *string {
	if err == nil {
		return nil
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return strPtr("NXDOMAIN")
		}
		if dnsErr.IsTimeout {
			return strPtr("TIMEOUT")
		}
	}

	lowered := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lowered, "no such host"):
		return strPtr("NXDOMAIN")
	case strings.Contains(lowered, "timed out"), strings.Contains(lowered, "i/o timeout"):
		return strPtr("TIMEOUT")
	case strings.Contains(lowered, "servfail"), strings.Contains(lowered, "server misbehaving"):
		return strPtr("SERVFAIL")
	case strings.Contains(lowered, "no data"):
		return strPtr("ENODATA")
	default:
		return nil
	}
}

func getResolver() string {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "system"
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "nameserver ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		return strings.TrimSuffix(fields[1], "#53")
	}

	return "system"
}

func queryPublicResolver(host string, systemIPs []string, timeoutMs int) *types.ResolverComparison {
	limit := timeoutMs
	if limit <= 0 || limit > 3000 {
		limit = 3000
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(limit)*time.Millisecond)
	defer cancel()

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _ string, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: time.Duration(limit) * time.Millisecond}
			return d.DialContext(ctx, "udp", "1.1.1.1:53")
		},
	}

	ips, err := resolver.LookupIP(ctx, "ip4", host)
	if err != nil {
		return nil
	}
	publicIPs := dedupeIPStrings(ips)
	splitHorizon := detectSplitHorizon(systemIPs, publicIPs)

	return &types.ResolverComparison{
		PublicIPs:    publicIPs,
		SplitHorizon: splitHorizon,
	}
}

func detectSplitHorizon(systemIPs []string, publicIPs []string) bool {
	systemHasPrivate := false
	for _, ip := range systemIPs {
		if IsPrivateIP(ip) {
			systemHasPrivate = true
			break
		}
	}

	publicHasPrivate := false
	for _, ip := range publicIPs {
		if IsPrivateIP(ip) {
			publicHasPrivate = true
			break
		}
	}

	return systemHasPrivate && !publicHasPrivate && len(publicIPs) > 0
}

func IsPrivateIP(ip string) bool {
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "192.168.") {
		return true
	}
	if !strings.HasPrefix(ip, "172.") {
		return false
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return false
	}

	parts := strings.Split(ip, ".")
	if len(parts) < 2 {
		return false
	}
	second, err := strconv.Atoi(parts[1])
	if err != nil {
		return false
	}
	return second >= 16 && second <= 31
}

func elapsedMs(start time.Time) int64 {
	return time.Since(start).Milliseconds()
}

func strPtr(s string) *string {
	return &s
}
