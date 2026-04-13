package checks

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
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

const (
	ipapiCacheTTL           = 1 * time.Hour
	ipapiStaleIfErrorTTL    = 24 * time.Hour
	ipapiNegativeCacheTTL   = 5 * time.Minute
	networkContextCacheFile = "network-context.json"
)

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
		CountryName:   ipResult.countryName,
		ISP:           ipResult.isp,
		ASN:           ipResult.asn,
		ResolverIP:    resolverIP,
		ResolverLabel: resolverLabel,
	}
}

type publicIPResult struct {
	ip          *string
	country     *string
	countryName *string
	isp         *string
	asn         *string
}

func fetchPublicIPAndCountry() publicIPResult {
	return resolvePublicIPWithCache(
		readCachedPublicIP,
		fetchPublicIPFromAPI,
		writeCachedPublicIP,
		hasRecentIPAPIFailure,
		markIPAPIFailure,
		clearIPAPIFailure,
	)
}

type cacheReader func(maxAge time.Duration) publicIPResult
type remoteFetcher func() publicIPResult
type cacheWriter func(data publicIPResult)
type failureReader func(maxAge time.Duration) bool
type failureMarker func()
type failureClearer func()

func resolvePublicIPWithCache(
	readCache cacheReader,
	fetchRemote remoteFetcher,
	writeCache cacheWriter,
	hasRecentFailure failureReader,
	markFailure failureMarker,
	clearFailure failureClearer,
) publicIPResult {
	if cached := readCache(ipapiCacheTTL); cached.ip != nil {
		return cached
	}

	if hasRecentFailure(ipapiNegativeCacheTTL) {
		if stale := readCache(ipapiStaleIfErrorTTL); stale.ip != nil {
			return stale
		}
		return publicIPResult{}
	}

	fetched := fetchRemote()
	if fetched.ip != nil {
		writeCache(fetched)
		clearFailure()
		return fetched
	}

	markFailure()
	if stale := readCache(ipapiStaleIfErrorTTL); stale.ip != nil {
		return stale
	}

	return publicIPResult{}
}

func fetchPublicIPFromAPI() publicIPResult {
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
		CountryName string `json:"country_name"`
		Org         string `json:"org"`
		ASN         string `json:"asn"`
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
	var countryName *string
	if payload.CountryName != "" && len(payload.CountryName) <= 120 {
		cn := payload.CountryName
		countryName = &cn
	}
	var isp *string
	if payload.Org != "" && len(payload.Org) <= 120 {
		i := payload.Org
		isp = &i
	}
	var asn *string
	if payload.ASN != "" && len(payload.ASN) <= 32 {
		a := payload.ASN
		asn = &a
	}

	return publicIPResult{
		ip:          &ip,
		country:     country,
		countryName: countryName,
		isp:         isp,
		asn:         asn,
	}
}

type cachePayload struct {
	FetchedAt   string `json:"fetchedAt"`
	LastFailure string `json:"lastFailureAt,omitempty"`
	IP          string `json:"ip"`
	CountryCode string `json:"countryCode,omitempty"`
	CountryName string `json:"countryName,omitempty"`
	ISP         string `json:"isp,omitempty"`
	ASN         string `json:"asn,omitempty"`
}

func readCachedPublicIP(maxAge time.Duration) publicIPResult {
	payload, ok := readCachePayload()
	if !ok {
		return publicIPResult{}
	}

	fetchedAt, err := time.Parse(time.RFC3339, payload.FetchedAt)
	if err != nil {
		return publicIPResult{}
	}
	if time.Since(fetchedAt) > maxAge {
		return publicIPResult{}
	}

	return sanitizePublicIPPayload(payload)
}

func writeCachedPublicIP(data publicIPResult) {
	if data.ip == nil {
		return
	}

	payload := cachePayload{
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
		IP:        *data.ip,
	}
	if data.country != nil {
		payload.CountryCode = *data.country
	}
	if data.countryName != nil {
		payload.CountryName = *data.countryName
	}
	if data.isp != nil {
		payload.ISP = *data.isp
	}
	if data.asn != nil {
		payload.ASN = *data.asn
	}

	writeCachePayload(payload)
}

func sanitizePublicIPPayload(payload cachePayload) publicIPResult {
	if payload.IP == "" || len(payload.IP) > 50 {
		return publicIPResult{}
	}

	ip := payload.IP
	result := publicIPResult{ip: &ip}

	if payload.CountryCode != "" && len(payload.CountryCode) <= 8 {
		c := payload.CountryCode
		result.country = &c
	}
	if payload.CountryName != "" && len(payload.CountryName) <= 120 {
		cn := payload.CountryName
		result.countryName = &cn
	}
	if payload.ISP != "" && len(payload.ISP) <= 120 {
		isp := payload.ISP
		result.isp = &isp
	}
	if payload.ASN != "" && len(payload.ASN) <= 32 {
		asn := payload.ASN
		result.asn = &asn
	}

	return result
}

func networkContextCachePath() (string, error) {
	if override := strings.TrimSpace(os.Getenv("ACCESSYO_CACHE_DIR")); override != "" {
		return filepath.Join(override, "accessyo", networkContextCacheFile), nil
	}

	baseDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(baseDir, "accessyo", networkContextCacheFile), nil
}

func hasRecentIPAPIFailure(maxAge time.Duration) bool {
	payload, ok := readCachePayload()
	if !ok || payload.LastFailure == "" {
		return false
	}

	lastFailure, err := time.Parse(time.RFC3339, payload.LastFailure)
	if err != nil {
		return false
	}
	return time.Since(lastFailure) <= maxAge
}

func markIPAPIFailure() {
	payload, ok := readCachePayload()
	if !ok {
		payload = cachePayload{}
	}
	payload.LastFailure = time.Now().UTC().Format(time.RFC3339)
	writeCachePayload(payload)
}

func clearIPAPIFailure() {
	payload, ok := readCachePayload()
	if !ok || payload.LastFailure == "" {
		return
	}
	payload.LastFailure = ""
	writeCachePayload(payload)
}

func readCachePayload() (cachePayload, bool) {
	cachePath, err := networkContextCachePath()
	if err != nil {
		return cachePayload{}, false
	}

	data, err := os.ReadFile(cachePath)
	if err != nil {
		return cachePayload{}, false
	}

	var payload cachePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return cachePayload{}, false
	}
	return payload, true
}

func writeCachePayload(payload cachePayload) {
	cachePath, err := networkContextCachePath()
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		return
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return
	}
	_ = os.WriteFile(cachePath, encoded, 0o644)
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
