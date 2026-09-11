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
	taskTimes map[[16]byte]time.Time
	Schedules []*Schedule
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

// Schedule is a server-side recurring task. On every beacon pass the session
// queue is refilled from due schedules, so the operator gets persistence
// without touching the agent's loop.
type Schedule struct {
	Type     uint8
	Data     []byte
	Interval time.Duration
	NextRun  time.Time
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
		taskTimes: make(map[[16]byte]time.Time),
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

// PeekResults returns a copy of the stored results without draining them.
func (s *Session) PeekResults() []*Result {
	s.ResultsMu.Lock()
	defer s.ResultsMu.Unlock()
	results := make([]*Result, len(s.Results))
	for i, r := range s.Results {
		cp := *r
		cp.Output = append([]byte(nil), r.Output...)
		results[i] = &cp
	}
	return results
}

// PeekQueue returns a copy of the queued tasks without dequeuing them.
func (s *Session) PeekQueue() []*Task {
	s.QueueMu.Lock()
	defer s.QueueMu.Unlock()
	tasks := make([]*Task, len(s.Queue))
	for i, t := range s.Queue {
		cp := *t
		cp.Data = append([]byte(nil), t.Data...)
		tasks[i] = &cp
	}
	return tasks
}

func (s *Session) AddSchedule(taskType uint8, data []byte, interval time.Duration) {
	s.QueueMu.Lock()
	defer s.QueueMu.Unlock()
	s.Schedules = append(s.Schedules, &Schedule{
		Type:     taskType,
		Data:     append([]byte(nil), data...),
		Interval: interval,
		NextRun:  time.Now().Add(interval),
	})
}

func (s *Session) DueSchedules(now time.Time) []*Task {
	s.QueueMu.Lock()
	defer s.QueueMu.Unlock()
	var due []*Task
	for _, sch := range s.Schedules {
		if now.After(sch.NextRun) {
			t := &Task{Type: sch.Type, Data: append([]byte(nil), sch.Data...)}
			due = append(due, t)
			sch.NextRun = now.Add(sch.Interval)
		}
	}
	return due
}

func (s *Session) ShowSchedules() []Schedule {
	s.QueueMu.Lock()
	defer s.QueueMu.Unlock()
	out := make([]Schedule, len(s.Schedules))
	for i, sch := range s.Schedules {
		out[i] = *sch
	}
	return out
}

func (s *Session) ClearSchedules() {
	s.QueueMu.Lock()
	defer s.QueueMu.Unlock()
	s.Schedules = nil
}

func (s *Session) RecordTask(id [16]byte) {
	s.QueueMu.Lock()
	defer s.QueueMu.Unlock()
	if s.taskTimes == nil {
		s.taskTimes = make(map[[16]byte]time.Time)
	}
	s.taskTimes[id] = time.Now()
}

func (s *Session) TaskElapsed(id [16]byte) time.Duration {
	s.QueueMu.Lock()
	defer s.QueueMu.Unlock()
	t, ok := s.taskTimes[id]
	if !ok {
		return 0
	}
	delete(s.taskTimes, id)
	return time.Since(t)
}
