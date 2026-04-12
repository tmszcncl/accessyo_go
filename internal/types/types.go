package types

type NetworkContext struct {
	PublicIP      *string
	Country       *string
	ResolverIP    string
	ResolverLabel *string
}

type IpCheckResult struct {
	Ok         bool
	StatusCode *int
	DurationMs int64
	Error      *string
}

type WwwCheckResult struct {
	Kind string
}

type HstsInfo struct {
	Raw               string
	MaxAge            int
	IncludeSubDomains bool
	Preload           bool
}

type HttpResult struct {
	Ok                bool
	DurationMs        int64
	StatusCode        *int
	Redirects         []string
	Headers           map[string]string
	Error             *string
	BlockedBy         *string
	CDN               *string
	IPv4              *IpCheckResult
	IPv6              *IpCheckResult
	BrowserStatusCode *int
	BrowserDiffers    *bool
	WwwCheck          *WwwCheckResult
	HSTS              *HstsInfo
}

type TcpResult struct {
	Ok         bool
	DurationMs int64
	Port       int
	Error      *string
}

type TlsResult struct {
	Ok                bool
	DurationMs        int64
	Protocol          *string
	Cipher            *string
	AlpnProtocol      *string
	CertIssuer        *string
	CertValidTo       *string
	CertExpired       *bool
	CertDaysRemaining *int
	Error             *string
}

type DnsResult struct {
	Ok          bool
	DurationMs  int64
	Resolver    string
	ARecords    []string
	AaaaRecords []string
	TTL         *uint32
	CDN         *string
	Error       *string
	ErrorCode   *string
}
