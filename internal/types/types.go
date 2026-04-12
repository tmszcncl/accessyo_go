package types

type HttpResult struct {
	Ok         bool
	DurationMs int64
	StatusCode *int
	Redirects  []string
	Headers    map[string]string
	Error      *string
	BlockedBy  *string
}

type TcpResult struct {
	Ok         bool
	DurationMs int64
	Port       int
	Error      *string
}

type TlsResult struct {
	Ok          bool
	DurationMs  int64
	Protocol    *string
	Cipher      *string
	CertIssuer  *string
	CertValidTo *string
	CertExpired *bool
	Error       *string
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
