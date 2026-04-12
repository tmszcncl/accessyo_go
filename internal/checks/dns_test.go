package checks

import "testing"

func TestIsPrivateIP(t *testing.T) {
	t.Run("returns true for 10.x.x.x", func(t *testing.T) {
		if !IsPrivateIP("10.0.0.1") {
			t.Fatalf("expected private")
		}
		if !IsPrivateIP("10.255.255.255") {
			t.Fatalf("expected private")
		}
	})

	t.Run("returns true for 192.168.x.x", func(t *testing.T) {
		if !IsPrivateIP("192.168.1.1") {
			t.Fatalf("expected private")
		}
		if !IsPrivateIP("192.168.0.100") {
			t.Fatalf("expected private")
		}
	})

	t.Run("returns true for 172.16-31.x.x", func(t *testing.T) {
		if !IsPrivateIP("172.16.0.1") {
			t.Fatalf("expected private")
		}
		if !IsPrivateIP("172.31.255.255") {
			t.Fatalf("expected private")
		}
		if !IsPrivateIP("172.20.10.1") {
			t.Fatalf("expected private")
		}
	})

	t.Run("returns false for 172.15.x.x and 172.32.x.x", func(t *testing.T) {
		if IsPrivateIP("172.15.0.1") {
			t.Fatalf("expected public")
		}
		if IsPrivateIP("172.32.0.1") {
			t.Fatalf("expected public")
		}
	})

	t.Run("returns true for loopback 127.x.x.x", func(t *testing.T) {
		if !IsPrivateIP("127.0.0.1") {
			t.Fatalf("expected private")
		}
	})

	t.Run("returns false for public IPs", func(t *testing.T) {
		if IsPrivateIP("8.8.8.8") {
			t.Fatalf("expected public")
		}
		if IsPrivateIP("104.21.5.10") {
			t.Fatalf("expected public")
		}
		if IsPrivateIP("1.1.1.1") {
			t.Fatalf("expected public")
		}
	})
}

func TestDetectSplitHorizon(t *testing.T) {
	t.Run("true when system returns private and public resolver returns public", func(t *testing.T) {
		got := detectSplitHorizon([]string{"10.0.0.5"}, []string{"104.21.5.10"})
		if !got {
			t.Fatalf("expected split-horizon")
		}
	})

	t.Run("false when both return public", func(t *testing.T) {
		got := detectSplitHorizon([]string{"104.21.5.10"}, []string{"104.21.5.10"})
		if got {
			t.Fatalf("expected no split-horizon")
		}
	})

	t.Run("false when public resolver has no answer", func(t *testing.T) {
		got := detectSplitHorizon([]string{"10.0.0.5"}, []string{})
		if got {
			t.Fatalf("expected no split-horizon")
		}
	})
}
