package commands

import (
	"time"

	"github.com/tmszcncl/accessyo_go/internal/summary"
	"github.com/tmszcncl/accessyo_go/internal/types"
)

type JsonOutput struct {
	Host      string      `json:"host"`
	Timestamp string      `json:"timestamp"`
	Checks    JsonChecks  `json:"checks"`
	Summary   JsonSummary `json:"summary"`
}

type JsonChecks struct {
	DNS  types.DnsResult   `json:"dns"`
	TCP  *types.TcpResult  `json:"tcp"`
	TLS  *types.TlsResult  `json:"tls"`
	HTTP *types.HttpResult `json:"http"`
}

type JsonSummary struct {
	OK           bool              `json:"ok"`
	Status       string            `json:"status"`
	Explanation  string            `json:"explanation"`
	Warnings     []summary.Warning `json:"warnings"`
	Problem      *string           `json:"problem"`
	LikelyCause  *string           `json:"likelyCause"`
	WhatYouCanDo []string          `json:"whatYouCanDo"`
	TotalMs      int64             `json:"totalMs"`
}

func buildJSONOutput(host string, dns types.DnsResult, tcp *types.TcpResult, tls *types.TlsResult, httpResult *types.HttpResult) JsonOutput {
	s := summary.Build(summary.Input{
		DNS:  dns,
		TCP:  tcp,
		TLS:  tls,
		HTTP: httpResult,
	})

	totalMs := dns.DurationMs
	if tcp != nil {
		totalMs += tcp.DurationMs
	}
	if tls != nil {
		totalMs += tls.DurationMs
	}
	if httpResult != nil {
		totalMs += httpResult.DurationMs
	}

	return JsonOutput{
		Host:      host,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Checks: JsonChecks{
			DNS:  dns,
			TCP:  tcp,
			TLS:  tls,
			HTTP: httpResult,
		},
		Summary: JsonSummary{
			OK:           s.AllOK,
			Status:       string(s.Status),
			Explanation:  s.Explanation,
			Warnings:     s.Warnings,
			Problem:      s.Problem,
			LikelyCause:  s.LikelyCause,
			WhatYouCanDo: s.WhatYouCanDo,
			TotalMs:      totalMs,
		},
	}
}
