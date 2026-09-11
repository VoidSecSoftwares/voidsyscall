package channels

import (
	"bytes"
	"testing"
	"time"
)

func TestMessageRoundTrip(t *testing.T) {
	msg := &Message{}
	msg.ID = [16]byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	msg.Type = 0x42
	msg.Data = []byte("hello voidsyscall")

	buf := newMessageBuffer(msg)
	back, err := parseMessageBuffer(buf)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if back.Type != msg.Type {
		t.Errorf("type mismatch: got %x want %x", back.Type, msg.Type)
	}
	if !bytes.Equal(back.Data, msg.Data) {
		t.Errorf("data mismatch: got %q want %q", back.Data, msg.Data)
	}
	if back.ID != msg.ID {
		t.Errorf("id mismatch: got %x want %x", back.ID, msg.ID)
	}
}

func TestParseMessageTooShort(t *testing.T) {
	if _, err := parseMessageBuffer([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for short buffer")
	}
}

func TestParseTruncatedPayload(t *testing.T) {
	msg := &Message{Type: 1, Data: []byte("abc")}
	buf := newMessageBuffer(msg)
	if _, err := parseMessageBuffer(buf[:len(buf)-2]); err != nil {
		t.Fatalf("truncated payload parse should only drop data, got err: %v", err)
	}
}

func TestEncodeUint16(t *testing.T) {
	got := encodeUint16(0x1234)
	if !bytes.Equal(got, []byte{0x12, 0x34}) {
		t.Errorf("expected big-endian [0x12 0x34], got %v", got)
	}
}

func TestGetJitter(t *testing.T) {
	for min, max := range map[int]int{5: 30, 1: 1, 0: 0, 10: 10} {
		d := getJitter(min, max)
		secs := int(d / time.Second)
		if secs < min || secs > max {
			t.Errorf("jitter(%d,%d) = %ds out of range", min, max, secs)
		}
		if min == max && secs != min {
			t.Errorf("equal bounds jitter = %ds, want %ds", secs, min)
		}
	}
}

func TestDoHLabelRoundTrip(t *testing.T) {
	msg := &Message{}
	msg.ID = [16]byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6, 5, 4}
	msg.Type = 0x01
	msg.Data = []byte{0x16, 0x05, 0x00, 0x00, 0x00}
	buf := newMessageBuffer(msg)

	label := encodeDoHLabel(buf)
	dec, err := decodeDoHLabel(label)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	back, err := parseMessageBuffer(dec)
	if err != nil {
		t.Fatalf("parse decoded: %v", err)
	}
	if !bytes.Equal(back.Data, msg.Data) || back.Type != msg.Type || back.ID != msg.ID {
		t.Fatal("round-trip mismatch")
	}
}

func TestDoHLabelPaddingVariants(t *testing.T) {
	for _, data := range [][]byte{nil, {1}, {1, 2}, {1, 2, 3}, {1, 2, 3, 4}, {1, 2, 3, 4, 5}, {1, 2, 3, 4, 5, 6}, {1, 2, 3, 4, 5, 6, 7}} {
		dec, err := decodeDoHLabel(encodeDoHLabel(data))
		if err != nil {
			t.Fatalf("len %d: %v", len(data), err)
		}
		if !bytes.Equal(dec, data) {
			t.Fatalf("len %d: got %v want %v", len(data), dec, data)
		}
	}
}
