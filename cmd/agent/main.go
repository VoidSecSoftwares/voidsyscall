//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/VoidSecSoftwares/voidsyscall/agent"
)

func main() {
	configPath := flag.String("c", "", "Config file path")
	flag.Parse()

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "Usage: voidsyscall-agent -c <config.json>")
		os.Exit(1)
	}

	cfg, err := agent.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Load config: %v\n", err)
		os.Exit(1)
	}

	a, err := agent.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] Init agent: %v\n", err)
		os.Exit(1)
	}

	defer a.Stop()
	a.Run()
}
