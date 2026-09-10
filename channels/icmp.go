package channels

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

type ICMPChannel struct {
	config *Config
	conn   *net.IPConn
	running bool
	mu     sync.Mutex
}

func newICMPChannel(config *Config) (*ICMPChannel, error) {
	return &ICMPChannel{
		config: config,
	}, nil
}

func (ic *ICMPChannel) Type() ChannelType {
	return ChannelICMP
}

func (ic *ICMPChannel) Send(ctx context.Context, msg *Message) (*Message, error) {
	addr := ic.config.ICMPAddr
	if addr == "" {
		addr = "127.0.0.1"
	}

	conn, err := net.DialTimeout("ip4:icmp", addr, time.Duration(ic.config.TimeoutSec)*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial ICMP: %w", err)
	}
	defer conn.Close()

	payload := newMessageBuffer(msg)

	// ICMP Echo Request with our payload
	icmpMsg := buildICMPEcho(payload, uint16(time.Now().UnixNano()&0xFFFF))

	_, err = conn.Write(icmpMsg)
	if err != nil {
		return nil, fmt.Errorf("send ICMP: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(time.Duration(ic.config.TimeoutSec) * time.Second))

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("receive ICMP: %w", err)
	}

	// Parse ICMP Echo Reply
	replyPayload, err := parseICMPEcho(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("parse ICMP reply: %w", err)
	}

	return parseMessageBuffer(replyPayload)
}

func (ic *ICMPChannel) Listen(ctx context.Context, addr string, handler func(*Message) *Message) error {
	listener, err := net.ListenPacket("ip4:icmp", addr)
	if err != nil {
		return fmt.Errorf("listen ICMP: %w", err)
	}
	defer listener.Close()
	ic.conn = listener.(*net.IPConn)
	ic.running = true

	buf := make([]byte, 1500)

	for ic.running {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		listener.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remote, err := listener.ReadFrom(buf)
		if err != nil {
			continue
		}

		go ic.handleICMP(listener, remote, buf[:n], handler)
	}

	return nil
}

func (ic *ICMPChannel) handleICMP(listener net.PacketConn, remote net.Addr, packet []byte, handler func(*Message) *Message) {
	if len(packet) < 8 {
		return
	}

	// ICMP header: Type(1) Code(1) Checksum(2) ID(2) Sequence(2)
	icmpType := packet[0]
	if icmpType != 8 { // Echo Request
		return
	}

	payload := packet[8:]
	msg, err := parseMessageBuffer(payload)
	if err != nil {
		return
	}

	resp := handler(msg)
	if resp == nil {
		return
	}

	replyPayload := newMessageBuffer(resp)
	id := binary.BigEndian.Uint16(packet[4:6])
	seq := binary.BigEndian.Uint16(packet[6:8])

	reply := buildICMPEchoWithID(id, seq, replyPayload)
	listener.WriteTo(reply, remote)
}

func (ic *ICMPChannel) Close() error {
	ic.running = false
	if ic.conn != nil {
		return ic.conn.Close()
	}
	return nil
}

func buildICMPEcho(payload []byte, id uint16) []byte {
	return buildICMPEchoWithID(id, 1, payload)
}

func buildICMPEchoWithID(id, seq uint16, payload []byte) []byte {
	msg := make([]byte, 8+len(payload))
	msg[0] = 8 // Echo Request
	msg[1] = 0 // Code
	// Checksum placeholder at msg[2:4]
	binary.BigEndian.PutUint16(msg[4:6], id)
	binary.BigEndian.PutUint16(msg[6:8], seq)
	copy(msg[8:], payload)

	// Calculate checksum
	checksum := icmpChecksum(msg)
	binary.BigEndian.PutUint16(msg[2:4], checksum)

	return msg
}

func parseICMPEcho(packet []byte) ([]byte, error) {
	if len(packet) < 8 {
		return nil, fmt.Errorf("packet too short")
	}

	icmpType := packet[0]
	if icmpType != 0 { // Echo Reply
		return nil, fmt.Errorf("not an echo reply: type %d", icmpType)
	}

	return packet[8:], nil
}

func icmpChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)
	index := 0

	for length > 1 {
		sum += uint32(binary.BigEndian.Uint16(data[index : index+2]))
		index += 2
		length -= 2
	}

	if length > 0 {
		sum += uint32(data[index]) << 8
	}

	sum = (sum >> 16) + (sum & 0xFFFF)
	sum += sum >> 16

	return ^uint16(sum)
}
