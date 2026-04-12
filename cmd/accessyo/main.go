package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/tmszcncl/accessyo_go/internal/commands"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		printUsage()
		os.Exit(2)
	}

	var err error
	if args[0] == "diagnose" {
		timeout, jsonOutput, remaining, parseErr := parseOptions(args[1:])
		if parseErr != nil {
			printUsage()
			os.Exit(2)
		}
		if len(remaining) != 1 {
			printUsage()
			os.Exit(2)
		}
		err = commands.Diagnose(remaining[0], 443, timeout, jsonOutput)
	} else {
		timeout, jsonOutput, remaining, parseErr := parseOptions(args)
		if parseErr != nil {
			printUsage()
			os.Exit(2)
		}
		if len(remaining) == 0 {
			printUsage()
			os.Exit(2)
		}
		if len(remaining) == 1 {
			err = commands.Diagnose(remaining[0], 443, timeout, jsonOutput)
		} else {
			err = commands.Batch(remaining, timeout, jsonOutput)
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  accessyo [--timeout <ms>] [--json] <host...>")
	fmt.Fprintln(os.Stderr, "  accessyo diagnose [--timeout <ms>] [--json] <host>")
}

func normalizedTimeout(raw int) int {
	if raw < 500 {
		return 500
	}
	return raw
}

func parseOptions(args []string) (timeoutMs int, jsonOutput bool, positionals []string, err error) {
	timeoutMs = 5000
	positionals = make([]string, 0)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--json":
			jsonOutput = true
		case strings.HasPrefix(arg, "--timeout="):
			raw := strings.TrimPrefix(arg, "--timeout=")
			value, parseErr := strconv.Atoi(raw)
			if parseErr != nil {
				return 0, false, nil, parseErr
			}
			timeoutMs = normalizedTimeout(value)
		case arg == "--timeout":
			if i+1 >= len(args) {
				return 0, false, nil, fmt.Errorf("missing value for --timeout")
			}
			value, parseErr := strconv.Atoi(args[i+1])
			if parseErr != nil {
				return 0, false, nil, parseErr
			}
			timeoutMs = normalizedTimeout(value)
			i++
		case strings.HasPrefix(arg, "--"):
			return 0, false, nil, fmt.Errorf("unknown option: %s", arg)
		default:
			positionals = append(positionals, arg)
		}
	}

	return timeoutMs, jsonOutput, positionals, nil
}
