package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// webSessionView is the JSON-safe shape served by /api/sessions.
type webSessionView struct {
	ID         string `json:"id"`
	Channel    string `json:"channel"`
	LastBeacon string `json:"last_beacon"`
	Queued     int    `json:"queued_tasks"`
	Results    int    `json:"results"`
	Info       string `json:"info,omitempty"`
}

// StartWebUI exposes a read-only operator dashboard over plain HTTP/JSON
// (stdlib only). It intentionally mirrors the C2 board, not a new impl.
func (s *Server) startWebUI() {
	addr := s.config.WebAddr
	if addr == "" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, webDashboardHTML)
	})
	mux.HandleFunc("/api/sessions", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, s.webSessions())
	})
	mux.HandleFunc("/api/sessions/", func(w http.ResponseWriter, r *http.Request) {
		idHex := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
		id, ok := parseSessionIDHex(idHex)
		if !ok {
			http.Error(w, "bad session id", http.StatusBadRequest)
			return
		}
		sess, ok := s.sessions.Get(id)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, s.webSessionDetail(sess))
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		log.Printf("%s[+] Web UI:%s %s%s%s", AnsiGreen, AnsiReset, AnsiCyan, addr, AnsiReset)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("%s[-] Web UI error: %v%s", AnsiRed, err, AnsiReset)
		}
	}()
	go func() {
		<-s.ctx.Done()
		_ = srv.Close()
	}()
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) webSessions() []webSessionView {
	sessions := s.sessions.All()
	out := make([]webSessionView, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, webSessionView{
			ID:         fmt.Sprintf("%x", sess.ID[:8]),
			Channel:    sess.Channel,
			LastBeacon: sess.LastBeacon.Format(time.RFC3339),
			Queued:     len(sess.PeekQueue()),
			Results:    len(sess.PeekResults()),
			Info:       sess.Info["ua"],
		})
	}
	return out
}

type webTaskView struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Size int    `json:"size"`
}

type webResultView struct {
	ID     string `json:"id"`
	Status uint8  `json:"status"`
	Size   int    `json:"size"`
}

type webSessionDetail struct {
	ID      string          `json:"id"`
	Channel string          `json:"channel"`
	Key     string          `json:"key_sha256,omitempty"`
	Queue   []webTaskView   `json:"queue"`
	Results []webResultView `json:"results"`
}

func (s *Server) webSessionDetail(sess *Session) webSessionDetail {
	detail := webSessionDetail{
		ID:      fmt.Sprintf("%x", sess.ID[:8]),
		Channel: sess.Channel,
	}
	for _, t := range sess.PeekQueue() {
		detail.Queue = append(detail.Queue, webTaskView{
			ID:   fmt.Sprintf("%x", t.ID[:8]),
			Type: taskTypeName(TaskType(t.Type)),
			Size: len(t.Data),
		})
	}
	for _, r := range sess.PeekResults() {
		detail.Results = append(detail.Results, webResultView{
			ID:     fmt.Sprintf("%x", r.TaskID[:8]),
			Status: r.Status,
			Size:   len(r.Output),
		})
	}
	return detail
}

func parseSessionIDHex(s string) ([16]byte, bool) {
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

const webDashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>voidsyscall — operator board</title>
<style>
body{margin:0;font-family:ui-monospace,Consolas,monospace;background:#0d1117;color:#c9d1d9;padding:24px}
h1{font-size:18px;border-bottom:1px solid #30363d;padding-bottom:8px}
table{border-collapse:collapse;width:100%;margin-top:12px}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid #21262d}
th{color:#8b949e;font-weight:600}
td.id{color:#58a6ff}td.ok{color:#3fb950}
</style>
</head>
<body>
<h1>voidsyscall C2 — sessions</h1>
<div id="board">loading…</div>
<script>
async function refresh(){
  const r = await fetch('/api/sessions'); const s = await r.json();
  const b = document.getElementById('board');
  if(!s.length){ b.textContent='no active sessions'; return; }
  let html='<table><thead><tr><th>id</th><th>channel</th><th>last beacon</th><th>queued</th><th>results</th><th>ua</th></tr></thead><tbody>';
  for(const x of s){ html += '<tr><td class="id">'+x.id+'</td><td>'+x.channel+'</td><td>'+(x.last_beacon||'')+'</td><td>'+x.queued_tasks+'</td><td class="ok">'+x.results+'</td><td>'+ (x.info||'') +'</td></tr>'; }
  b.innerHTML = html + '</tbody></table>';
}
refresh(); setInterval(refresh, 5000);
</script>
</body>
</html>`
