package main

import (
	"fmt"
	"os"

	"github.com/tmszcncl/accessyo_go/internal/commands"
)

func main() {
	host, ok := parseArgs(os.Args[1:])
	if !ok {
		printUsage()
		os.Exit(2)
	}

	if err := commands.Diagnose(host, 443); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func parseArgs(args []string) (string, bool) {
	if len(args) == 1 {
		return args[0], true
	}

	if len(args) == 2 && args[0] == "diagnose" {
		return args[1], true
	}

	return "", false
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  accessyo <host>")
	fmt.Fprintln(os.Stderr, "  accessyo diagnose <host>")
}
