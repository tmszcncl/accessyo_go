package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	timeout := flag.Int("timeout", 5000, "per-check timeout in milliseconds")
	jsonOutput := flag.Bool("json", false, "output results as JSON")

	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: accessyo [--timeout <ms>] [--json] <host...>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Scaffold status:")
		fmt.Fprintln(os.Stderr, "  CLI functionality is being built.")
		fmt.Fprintln(os.Stderr, "")
		flag.PrintDefaults()
	}

	flag.Parse()
	hosts := flag.Args()

	if len(hosts) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	_ = timeout
	_ = jsonOutput

	fmt.Println("Accessyo Go CLI is in early development. Diagnostics are coming in the next commits.")
}
