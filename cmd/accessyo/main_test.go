package main

import "testing"

func TestParseOptions(t *testing.T) {
	t.Run("parses debug and json flags", func(t *testing.T) {
		timeout, jsonOutput, debugOutput, positionals, err := parseOptions([]string{"--json", "--debug", "google.com"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if timeout != 5000 {
			t.Fatalf("expected default timeout 5000, got %d", timeout)
		}
		if !jsonOutput {
			t.Fatalf("expected jsonOutput true")
		}
		if !debugOutput {
			t.Fatalf("expected debugOutput true")
		}
		if len(positionals) != 1 || positionals[0] != "google.com" {
			t.Fatalf("unexpected positionals: %#v", positionals)
		}
	})

	t.Run("returns error on unknown option", func(t *testing.T) {
		_, _, _, _, err := parseOptions([]string{"--unknown"})
		if err == nil {
			t.Fatalf("expected error")
		}
	})
}
