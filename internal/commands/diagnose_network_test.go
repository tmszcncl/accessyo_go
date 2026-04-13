package commands

import "testing"

func TestMaskPublicIP(t *testing.T) {
	t.Run("returns full IPv4 value", func(t *testing.T) {
		got := maskPublicIP("176.104.177.170")
		if got != "176.104.177.170" {
			t.Fatalf("expected full IPv4, got %q", got)
		}
	})

	t.Run("returns full IPv6 value", func(t *testing.T) {
		got := maskPublicIP("2a00:1450:4025:804::65")
		if got != "2a00:1450:4025:804::65" {
			t.Fatalf("expected full IPv6, got %q", got)
		}
	})
}
