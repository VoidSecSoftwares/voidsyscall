package channels

import (
	"encoding/base32"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// buildHTTPMux registers the standard POST beacon endpoint and a landing
// page handler on a fresh ServeMux. The beacon is URL-path-filtered to the
// configured BeaconPath; all other requests get an innocuous HTML page.
func buildHTTPMux(ch *HTTPChannel, handler func(*Message) *Message) *http.ServeMux {
	mux := http.NewServeMux()
	path := ch.config.BeaconPath
	if path == "" {
		path = "/api/v2/health"
	}

	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()
		msg, err := parseMessageBuffer(body)
		if err != nil {
			http.Error(w, "parse error", http.StatusBadRequest)
			return
		}
		resp := handler(msg)
		if resp == nil {
			http.Error(w, "no response", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write(newMessageBuffer(resp))
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>Hello World</h1></body></html>")
	})
	return mux
}

// buildDoHMux registers the DoH server-side handler that decodes base32
// labels, dispatches the message frame to the handler, and wraps the reply
// in a DNS-over-HTTPS JSON envelope.  The actual RPC query path is always
// /dns-query to match the RFC 8484 standard.
func buildDoHMux(ch *DOHChannel, handler func(*Message) *Message) *http.ServeMux {
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
		payload, err := decodeDoHLabel(parts[0])
		if err != nil {
			http.Error(w, "decode", http.StatusBadRequest)
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
		data := encodeDoHLabel(newMessageBuffer(resp))
		w.Header().Set("Content-Type", "application/dns-json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"Status":0,"Answer":[{"name":%q,"type":16,"TTL":60,"data":%q}]}`, qname, data)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "404 page not found\n")
	})
	return mux
}

// encodeDoHLabel base32-encodes a binary message frame into a single
// subdomain label with no trailing '=' padding.
func encodeDoHLabel(data []byte) string {
	return strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(data), "="))
}

// decodeDoHLabel reverses the label encoding: re-pad, upper-case, base32-decode.
func decodeDoHLabel(label string) ([]byte, error) {
	padded := strings.ToUpper(label)
	switch len(padded) % 8 {
	case 0:
	case 1, 2, 3, 4, 5, 6, 7:
		padded += strings.Repeat("=", 8-len(padded)%8)
	}
	return base32.StdEncoding.DecodeString(padded)
}
