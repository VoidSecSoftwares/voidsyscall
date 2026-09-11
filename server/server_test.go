package server

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

func testServer() *Server {
	return NewServer(&ServerConfig{})
}

func TestSessionManagerGetOrCreate(t *testing.T) {
	sm := NewSessionManager()
	var id [16]byte
	copy(id[:], []byte{1, 2, 3, 4, 5, 6, 7, 8})

	s := sm.GetOrCreate(id, []byte("key"), "https")
	if s == nil {
		t.Fatal("expected session")
	}
	s2 := sm.GetOrCreate(id, nil, "dns")
	if s2 != s {
		t.Fatal("GetOrCreate must return the existing session")
	}
	if len(sm.All()) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sm.All()))
	}
	sm.Remove(id)
	if len(sm.All()) != 0 {
		t.Fatal("remove failed")
	}
}

func TestEnqueueDequeueOrder(t *testing.T) {
	srv := testServer()
	sm := srv.sessions
	var id [16]byte
	copy(id[:], []byte("sess0001"))
	sess := sm.GetOrCreate(id, nil, "https")

	first := &Task{ID: makeTaskID(), Type: uint8(TaskShell), Data: []byte("whoami")}
	second := &Task{ID: makeTaskID(), Type: uint8(TaskProcs)}
	sess.EnqueueTask(first)
	sess.EnqueueTask(second)

	if got := sess.DequeueTask(); got != first {
		t.Fatal("FIFO violation on first dequeue")
	}
	if got := sess.DequeueTask(); got != second {
		t.Fatal("FIFO violation on second dequeue")
	}
	if got := sess.DequeueTask(); got != nil {
		t.Fatal("expected nil on empty queue")
	}
}

func TestRunningConcurrentQueues(t *testing.T) {
	sm := NewSessionManager()
	var id [16]byte
	copy(id[:], []byte("conc0001"))
	sess := sm.GetOrCreate(id, nil, "https")

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				sess.EnqueueTask(&Task{Type: uint8(TaskShell), Data: []byte("x")})
			}
		}()
	}
	wg.Wait()
	if len(sess.PeekQueue()) != 1600 {
		t.Fatalf("expected 1600 queued, got %d", len(sess.PeekQueue()))
	}
}

func TestDueSchedulesRefill(t *testing.T) {
	sm := NewSessionManager()
	var id [16]byte
	sess := sm.GetOrCreate(id, nil, "https")
	sess.AddSchedule(uint8(TaskShell), []byte("dir"), time.Second)

	t0 := time.Now()
	due := sess.DueSchedules(t0.Add(2 * time.Second))
	if len(due) != 1 {
		t.Fatalf("expected 1 due task, got %d", len(due))
	}
	if due[0].Type != uint8(TaskShell) || string(due[0].Data) != "dir" {
		t.Fatal("schedule payload mismatch")
	}
	// Next run was pushed forward; nothing is due right away.
	if more := sess.DueSchedules(t0); len(more) != 0 {
		t.Fatal("schedule should not fire twice")
	}
}

func TestStateRoundTrip(t *testing.T) {
	path := t.TempDir() + "/state.json"
	cfg := &ServerConfig{StateFile: path}
	srv := NewServer(cfg)

	var id [16]byte
	copy(id[:], []byte{0xAA, 0xBB, 0xCC, 0xDD, 1, 2, 3, 4})
	sess := srv.sessions.GetOrCreate(id, []byte("symmetric-key-32-bytes!"), "doh")
	sess.Info["ua"] = "curl/8"
	sess.EnqueueTask(&Task{ID: makeTaskID(), Type: uint8(TaskShell), Data: []byte("ipconfig")})
	sess.RecordTask(makeTaskID())
	sess.AddResult(&Result{TaskID: makeTaskID(), Status: 0, Output: []byte("ok")})
	sess.Schedules = append(sess.Schedules, &Schedule{
		Type: uint8(TaskProcs), Interval: 60 * time.Second, NextRun: time.Now().Add(time.Minute),
	})

	if err := srv.SaveState(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	srv2 := NewServer(cfg)
	if err := srv2.LoadState(path); err != nil {
		t.Fatalf("load: %v", err)
	}

	got, ok := srv2.sessions.Get(id)
	if !ok {
		t.Fatal("session not restored")
	}
	if string(got.Key) != "symmetric-key-32-bytes!" {
		t.Fatal("key mismatch after restore")
	}
	if got.Info["ua"] != "curl/8" {
		t.Fatal("info mismatch after restore")
	}
	if len(got.Queue) != 1 || string(got.Queue[0].Data) != "ipconfig" {
		t.Fatal("queue mismatch after restore")
	}
	if len(got.Results) != 1 || got.Results[0].Status != 0 {
		t.Fatal("results mismatch after restore")
	}
	if len(got.taskTimes) != 1 {
		t.Fatalf("taskTimes mismatch after restore: %d", len(got.taskTimes))
	}
	if len(got.Schedules) != 1 {
		t.Fatal("schedules mismatch after restore")
	}
}

func TestLoadMissingStateIsNoop(t *testing.T) {
	srv := testServer()
	if err := srv.LoadState(t.TempDir() + "/nope.json"); err != nil {
		t.Fatalf("missing state file should be a no-op, got: %v", err)
	}
}

func TestRunUploadWireFormat(t *testing.T) {
	srv := testServer()
	var id [16]byte
	sm := srv.sessions
	sess := sm.GetOrCreate(id, nil, "https")

	if err := srv.RunUpload(id, "C:\\tmp\\x.bin", []byte{1, 2, 3}); err != nil {
		t.Fatalf("queue upload: %v", err)
	}
	queued := sess.PeekQueue()
	if len(queued) != 1 {
		t.Fatalf("expected 1 task, got %d", len(queued))
	}
	raw := queued[0].Data
	if len(raw) < 2 {
		t.Fatal("wire frame too short")
	}
	pathLen := binary.LittleEndian.Uint16(raw[:2])
	if int(pathLen) != len("C:\\tmp\\x.bin") {
		t.Fatalf("pathLen mismatch: got %d", pathLen)
	}
	if string(raw[2:2+pathLen]) != "C:\\tmp\\x.bin" {
		t.Fatal("path payload mismatch")
	}
	payload := raw[2+pathLen:]
	if !equalBytes(payload, []byte{1, 2, 3}) {
		t.Fatal("payload mismatch")
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
