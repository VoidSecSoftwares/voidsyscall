package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// persistedSession mirrors the exported fields of Session/LDR so the JSON
// encoder never has to touch the mutex-protected internals.
type persistedSession struct {
	ID         [16]byte
	Key        []byte
	LastBeacon time.Time
	Queue      []*Task
	Results    []*Result
	Channel    string
	Info       map[string]string
	Schedules  []*Schedule
	TaskTimes  map[string]time.Time
}

type persistedState struct {
	Version  int
	SavedAt  time.Time
	Sessions []*persistedSession
}

// SaveState dumps sessions, queues, results and schedules so a long-running
// operation survives a restart.
func (s *Server) SaveState(path string) error {
	sessions := s.sessions.All()
	st := &persistedState{
		Version:  1,
		SavedAt:  time.Now(),
		Sessions: make([]*persistedSession, 0, len(sessions)),
	}

	for _, sess := range sessions {
		sess.QueueMu.Lock()
		queue := append([]*Task(nil), sess.Queue...)
		schedules := append([]*Schedule(nil), sess.Schedules...)
		taskTimes := make(map[string]time.Time, len(sess.taskTimes))
		for k, v := range sess.taskTimes {
			taskTimes[hex.EncodeToString(k[:])] = v
		}
		sess.QueueMu.Unlock()

		sess.ResultsMu.Lock()
		results := append([]*Result(nil), sess.Results...)
		sess.ResultsMu.Unlock()

		st.Sessions = append(st.Sessions, &persistedSession{
			ID:         sess.ID,
			Key:        append([]byte(nil), sess.Key...),
			LastBeacon: sess.LastBeacon,
			Queue:      queue,
			Results:    results,
			Channel:    sess.Channel,
			Info:       sess.Info,
			Schedules:  schedules,
			TaskTimes:  taskTimes,
		})
	}

	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// LoadState restores a previously saved state file. A missing file is not an
// error; the manager simply starts empty.
func (s *Server) LoadState(path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read state: %w", err)
	}

	var st persistedState
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("parse state: %w", err)
	}

	s.sessions.mu.Lock()
	defer s.sessions.mu.Unlock()
	for _, ps := range st.Sessions {
		sess := &Session{
			ID:         ps.ID,
			Key:        ps.Key,
			LastBeacon: ps.LastBeacon,
			Channel:    ps.Channel,
			Info:       ps.Info,
			Queue:      ps.Queue,
			Results:    ps.Results,
			Schedules:  ps.Schedules,
		}
		if sess.Info == nil {
			sess.Info = make(map[string]string)
		}
		sess.taskTimes = make(map[[16]byte]time.Time, len(ps.TaskTimes))
		for k, v := range ps.TaskTimes {
			kb, err := hex.DecodeString(k)
			if err != nil || len(kb) != 16 {
				continue
			}
			var id [16]byte
			copy(id[:], kb)
			sess.taskTimes[id] = v
		}
		s.sessions.sessions[sess.ID] = sess
	}
	_ = st.Version
	return nil
}
