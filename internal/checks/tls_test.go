package checks

import (
	"crypto/tls"
	"reflect"
	"testing"
)

func TestNewTLSConfig(t *testing.T) {
	cfg := newTLSConfig("example.com")

	if cfg.ServerName != "example.com" {
		t.Fatalf("expected ServerName to be example.com, got %q", cfg.ServerName)
	}

	wantProtos := []string{"h2", "http/1.1"}
	if !reflect.DeepEqual(cfg.NextProtos, wantProtos) {
		t.Fatalf("expected NextProtos %v, got %v", wantProtos, cfg.NextProtos)
	}
}

func TestNegotiatedALPN(t *testing.T) {
	t.Run("returns negotiated h2 protocol", func(t *testing.T) {
		got := negotiatedALPN(tls.ConnectionState{NegotiatedProtocol: "h2"})
		assertStringPtr(t, got, "h2")
	})

	t.Run("returns negotiated http/1.1 protocol", func(t *testing.T) {
		got := negotiatedALPN(tls.ConnectionState{NegotiatedProtocol: "http/1.1"})
		assertStringPtr(t, got, "http/1.1")
	})

	t.Run("returns nil when ALPN was not negotiated", func(t *testing.T) {
		got := negotiatedALPN(tls.ConnectionState{NegotiatedProtocol: ""})
		if got != nil {
			t.Fatalf("expected nil, got %q", *got)
		}
	})
}
