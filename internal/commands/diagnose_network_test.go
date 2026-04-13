package commands

import "testing"

func TestMaskPublicIP(t *testing.T) {
	t.Run("masks IPv4 to keep first two octets", func(t *testing.T) {
		got := maskPublicIP("176.104.177.170")
		if got != "176.104.xxx.xxx" {
			t.Fatalf("expected masked IPv4, got %q", got)
		}
	})

	t.Run("masks IPv6 to keep first two groups", func(t *testing.T) {
		got := maskPublicIP("2a00:1450:4025:804::65")
		if got != "2a00:1450:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx" {
			t.Fatalf("expected masked IPv6, got %q", got)
		}
	})
}

func TestFormatPublicIPForDisplay(t *testing.T) {
	ip := "176.104.177.170"
	if got := formatPublicIPForDisplay(ip, false); got != "176.104.xxx.xxx" {
		t.Fatalf("expected masked IP in default mode, got %q", got)
	}
	if got := formatPublicIPForDisplay(ip, true); got != ip {
		t.Fatalf("expected full IP in debug mode, got %q", got)
	}
}
