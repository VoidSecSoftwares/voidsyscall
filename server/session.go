package server

import (
	"sync"
	"time"
)

type Session struct {
	ID        [16]byte
	Key       []byte
	LastBeacon time.Time
	Queue     []*Task
	QueueMu   sync.Mutex
	Results   []*Result
	ResultsMu sync.Mutex
	Channel   string
	Info      map[string]string
}

type Task struct {
	ID   [16]byte
	Type uint8
	Data []byte
}

type Result struct {
	TaskID [16]byte
	Status uint8
	Output []byte
}

type SessionManager struct {
	sessions map[[16]byte]*Session
	mu       sync.RWMutex
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[[16]byte]*Session),
	}
}

func (sm *SessionManager) GetOrCreate(id [16]byte, key []byte, channel string) *Session {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if s, ok := sm.sessions[id]; ok {
		s.LastBeacon = time.Now()
		return s
	}

	s := &Session{
		ID:        id,
		Key:       key,
		LastBeacon: time.Now(),
		Channel:   channel,
		Info:      make(map[string]string),
	}
	sm.sessions[id] = s
	return s
}

func (sm *SessionManager) Get(id [16]byte) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, ok := sm.sessions[id]
	return s, ok
}

func (sm *SessionManager) All() []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sessions := make([]*Session, 0, len(sm.sessions))
	for _, s := range sm.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

func (sm *SessionManager) Remove(id [16]byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, id)
}

func (s *Session) EnqueueTask(task *Task) {
	s.QueueMu.Lock()
	defer s.QueueMu.Unlock()
	s.Queue = append(s.Queue, task)
}

func (s *Session) DequeueTask() *Task {
	s.QueueMu.Lock()
	defer s.QueueMu.Unlock()
	if len(s.Queue) == 0 {
		return nil
	}
	task := s.Queue[0]
	s.Queue = s.Queue[1:]
	return task
}

func (s *Session) AddResult(result *Result) {
	s.ResultsMu.Lock()
	defer s.ResultsMu.Unlock()
	s.Results = append(s.Results, result)
}

func (s *Session) GetResults() []*Result {
	s.ResultsMu.Lock()
	defer s.ResultsMu.Unlock()
	results := s.Results
	s.Results = nil
	return results
}
