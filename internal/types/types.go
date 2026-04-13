package types

type NetworkContext struct {
	PublicIP      *string `json:"publicIP,omitempty"`
	Country       *string `json:"country,omitempty"`
	CountryName   *string `json:"countryName,omitempty"`
	ISP           *string `json:"isp,omitempty"`
	ASN           *string `json:"asn,omitempty"`
	ResolverIP    string  `json:"resolverIP"`
	ResolverLabel *string `json:"resolverLabel,omitempty"`
}

type IpCheckResult struct {
	Ok         bool    `json:"ok"`
	StatusCode *int    `json:"statusCode,omitempty"`
	DurationMs int64   `json:"durationMs"`
	Error      *string `json:"error,omitempty"`
}

type WwwCheckResult struct {
	Kind string `json:"kind"`
}

type HstsInfo struct {
	Raw               string `json:"raw"`
	MaxAge            int    `json:"maxAge"`
	IncludeSubDomains bool   `json:"includeSubDomains"`
	Preload           bool   `json:"preload"`
}

type HttpResult struct {
	Ok                bool              `json:"ok"`
	DurationMs        int64             `json:"durationMs"`
	TTFB              *int64            `json:"ttfb,omitempty"`
	StatusCode        *int              `json:"statusCode,omitempty"`
	Redirects         []string          `json:"redirects"`
	Headers           map[string]string `json:"headers"`
	Error             *string           `json:"error,omitempty"`
	BlockedBy         *string           `json:"blockedBy,omitempty"`
	CDN               *string           `json:"cdn,omitempty"`
	IPv4              *IpCheckResult    `json:"ipv4,omitempty"`
	IPv6              *IpCheckResult    `json:"ipv6,omitempty"`
	BrowserStatusCode *int              `json:"browserStatusCode,omitempty"`
	BrowserDiffers    *bool             `json:"browserDiffers,omitempty"`
	WwwCheck          *WwwCheckResult   `json:"wwwCheck,omitempty"`
	HSTS              *HstsInfo         `json:"hsts,omitempty"`
}

type TcpResult struct {
	Ok         bool    `json:"ok"`
	DurationMs int64   `json:"durationMs"`
	Port       int     `json:"port"`
	Error      *string `json:"error,omitempty"`
}

type TlsResult struct {
	Ok                bool    `json:"ok"`
	DurationMs        int64   `json:"durationMs"`
	Protocol          *string `json:"protocol,omitempty"`
	Cipher            *string `json:"cipher,omitempty"`
	AlpnProtocol      *string `json:"alpnProtocol,omitempty"`
	HostnameMatch     *bool   `json:"hostnameMatch,omitempty"`
	CertIssuer        *string `json:"certIssuer,omitempty"`
	CertValidTo       *string `json:"certValidTo,omitempty"`
	CertExpired       *bool   `json:"certExpired,omitempty"`
	CertDaysRemaining *int    `json:"certDaysRemaining,omitempty"`
	Error             *string `json:"error,omitempty"`
}

type ResolverComparison struct {
	PublicIPs    []string `json:"publicIps"`
	SplitHorizon bool     `json:"splitHorizon"`
}

type DnsResult struct {
	Ok                 bool                `json:"ok"`
	DurationMs         int64               `json:"durationMs"`
	Resolver           string              `json:"resolver"`
	ARecords           []string            `json:"aRecords,omitempty"`
	AaaaRecords        []string            `json:"aaaaRecords,omitempty"`
	CNAME              *string             `json:"cname,omitempty"`
	TTL                *uint32             `json:"ttl,omitempty"`
	CDN                *string             `json:"cdn,omitempty"`
	ResolverComparison *ResolverComparison `json:"resolverComparison,omitempty"`
	Error              *string             `json:"error,omitempty"`
	ErrorCode          *string             `json:"errorCode,omitempty"`
}
