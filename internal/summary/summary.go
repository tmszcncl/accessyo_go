package summary

import "github.com/tmszcncl/accessyo_go/internal/types"

type Input struct {
	DNS  types.DnsResult
	TCP  types.TcpResult
	TLS  *types.TlsResult
	HTTP *types.HttpResult
}

type Result struct {
	AllOK        bool
	Problem      *string
	LikelyCause  *string
	WhatYouCanDo []string
}

func Build(input Input) Result {
	dns := input.DNS
	tcp := input.TCP
	tls := input.TLS
	http := input.HTTP

	if !dns.Ok {
		return Result{
			AllOK:       false,
			Problem:     strPtr("Domain cannot be resolved"),
			LikelyCause: strPtr("DNS misconfiguration or typo in domain name"),
			WhatYouCanDo: []string{
				"check domain spelling",
				"try a different DNS resolver (e.g. 1.1.1.1)",
				"try from a different network",
			},
		}
	}

	if !tcp.Ok {
		return Result{
			AllOK:       false,
			Problem:     strPtr("Cannot connect to server"),
			LikelyCause: strPtr("server is down or firewall is blocking the connection"),
			WhatYouCanDo: []string{
				"check if the service is running",
				"try from a different network",
				"disable VPN if active",
			},
		}
	}

	if tls != nil && !tls.Ok {
		return Result{
			AllOK:       false,
			Problem:     strPtr("Secure connection failed"),
			LikelyCause: strPtr("certificate issue or network interference (ISP / VPN)"),
			WhatYouCanDo: []string{
				"check certificate expiry",
				"try from a different network",
				"disable VPN if active",
			},
		}
	}

	if http != nil && !http.Ok {
		statusCode := 0
		if http.StatusCode != nil {
			statusCode = *http.StatusCode
		}

		if http.BlockedBy != nil || statusCode == 403 || statusCode == 503 {
			return Result{
				AllOK:       false,
				Problem:     strPtr("Request blocked"),
				LikelyCause: strPtr("CDN / firewall / WAF is blocking the request"),
				WhatYouCanDo: []string{
					"try from a different network (mobile vs WiFi)",
					"disable VPN if active",
					"contact the website owner",
				},
			}
		}

		if statusCode == 404 {
			return Result{
				AllOK:       false,
				Problem:     strPtr("Page not found (404)"),
				LikelyCause: strPtr("the URL does not exist on this server"),
				WhatYouCanDo: []string{
					"check the URL is correct",
					"contact the website owner",
				},
			}
		}

		if statusCode >= 500 {
			return Result{
				AllOK:       false,
				Problem:     strPtr("Server error"),
				LikelyCause: strPtr("the server is returning an error - likely a backend issue"),
				WhatYouCanDo: []string{
					"try again in a few minutes",
					"contact the website owner",
				},
			}
		}

		return Result{
			AllOK:       false,
			Problem:     strPtr("HTTP request failed"),
			LikelyCause: strPtr("unexpected response from server"),
			WhatYouCanDo: []string{
				"try from a different network",
				"contact the website owner",
			},
		}
	}

	return Result{
		AllOK:        true,
		Problem:      nil,
		LikelyCause:  nil,
		WhatYouCanDo: []string{},
	}
}

func strPtr(s string) *string {
	return &s
}
