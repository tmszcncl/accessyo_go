package checks

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tmszcncl/accessyo_go/internal/types"
)

var knownResolvers = map[string]string{
	"8.8.8.8":        "Google DNS",
	"8.8.4.4":        "Google DNS",
	"1.1.1.1":        "Cloudflare DNS",
	"1.0.0.1":        "Cloudflare DNS",
	"9.9.9.9":        "Quad9",
	"208.67.222.222": "OpenDNS",
	"208.67.220.220": "OpenDNS",
}

func GetNetworkContext() types.NetworkContext {
	ipResult := fetchPublicIPAndCountry()

	resolverIP := getSystemResolver()
	var resolverLabel *string
	if label, ok := knownResolvers[resolverIP]; ok {
		resolverLabel = &label
	}

	return types.NetworkContext{
		PublicIP:      ipResult.ip,
		Country:       ipResult.country,
		ResolverIP:    resolverIP,
		ResolverLabel: resolverLabel,
	}
}

type publicIPResult struct {
	ip      *string
	country *string
}

func fetchPublicIPAndCountry() publicIPResult {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://ipapi.co/json/", nil)
	if err != nil {
		return publicIPResult{}
	}
	req.Header.Set("User-Agent", "accessyo/0.1")

	resp, err := client.Do(req)
	if err != nil {
		return publicIPResult{}
	}
	defer resp.Body.Close()

	var payload struct {
		IP          string `json:"ip"`
		CountryCode string `json:"country_code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return publicIPResult{}
	}

	if payload.IP == "" || len(payload.IP) > 50 {
		return publicIPResult{}
	}

	ip := payload.IP
	var country *string
	if payload.CountryCode != "" {
		c := payload.CountryCode
		country = &c
	}

	return publicIPResult{
		ip:      &ip,
		country: country,
	}
}

func getSystemResolver() string {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "unknown"
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

	return "unknown"
}
