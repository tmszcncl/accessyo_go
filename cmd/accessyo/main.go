package main

import (
	"fmt"
	"os"

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
		if len(args) != 2 {
			printUsage()
			os.Exit(2)
		}
		err = commands.Diagnose(args[1], 443)
	} else if len(args) == 1 {
		err = commands.Diagnose(args[0], 443)
	} else {
		err = commands.Batch(args)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  accessyo <host...>")
	fmt.Fprintln(os.Stderr, "  accessyo diagnose <host>")
}
