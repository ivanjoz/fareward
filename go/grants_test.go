package fareward

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
)

// The layout src/store/grants.rs parses: one live user and one deleted one.
func TestAGrantBatchHasTheRustLayout(t *testing.T) {
	payload, next, err := encodeGrantBatch([]UserGrants{
		{CompanyID: 7, UserID: 42, Status: 1, Grants: []byte{0x01, 0x39}, SubGrants: []byte{0x02, 0x00, 0x20}},
		{CompanyID: 7, UserID: 43, Status: 1, Grants: []byte{0x01, 0x39}, Deleted: true},
	}, 0)
	if err != nil || next != 2 {
		t.Fatalf("next %d err %v", next, err)
	}
	want := []byte{
		0, 2,
		0, 0, 0, 7, 0, 0, 0, 42, 0, 1, 0, 2, 0x01, 0x39, 0, 3, 0x02, 0x00, 0x20,
		0, 0, 0, 7, 0, 0, 0, 43, 1, 0, 0, 0, 0, 0,
	}
	if !bytes.Equal(payload, want) {
		t.Fatalf("payload %v", payload)
	}
}

// A push larger than one frame is split, every frame fits, and nobody is sent twice or skipped.
func TestAPushIsSplitIntoFramesThatFit(t *testing.T) {
	users := make([]UserGrants, 3000)
	for index := range users {
		users[index] = UserGrants{CompanyID: 1 + int32(index/100), UserID: 1 + int32(index),
			Status: 1, Grants: bytes.Repeat([]byte{0x01, 0x39}, 4)}
	}
	stub := startMuxDaemonStub(t)
	installStubAsConfiguredFareward(t, stub)
	stub.mu.Lock()
	stub.answer = func(uint64, byte, []byte) (byte, []byte, bool) { return replyAck, nil, true }
	stub.mu.Unlock()

	done := make(chan error, 1)
	go func() { done <- PutUserGrants(context.Background(), users) }()

	seen := 0
	for seen < len(users) {
		frame := <-stub.frames
		if frame[0] != opcodePutGrants {
			t.Fatalf("opcode 0x%02X", frame[0])
		}
		declared := int(binary.BigEndian.Uint16(frame[1:3]))
		if declared > grantsMaxPayload {
			t.Fatalf("a %d-byte frame", declared)
		}
		payload := frame[3 : 3+declared]
		count := int(binary.BigEndian.Uint16(payload[:2]))
		firstUser := int32(binary.BigEndian.Uint32(payload[6:10]))
		if firstUser != users[seen].UserID {
			t.Fatalf("frame starts at user %d, want %d", firstUser, users[seen].UserID)
		}
		seen += count
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if seen != len(users) {
		t.Fatalf("sent %d of %d", seen, len(users))
	}
}

func TestAnInvalidUserIsRefusedBeforeSending(t *testing.T) {
	if _, _, err := encodeGrantBatch([]UserGrants{{CompanyID: 0, UserID: 1}}, 0); err == nil {
		t.Fatal("company 0 accepted")
	}
	huge := UserGrants{CompanyID: 1, UserID: 1, Grants: make([]byte, grantsMaxPayload)}
	if _, _, err := encodeGrantBatch([]UserGrants{huge}, 0); err == nil {
		t.Fatal("an entry larger than a frame accepted")
	}
}
