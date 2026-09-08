package fareward

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// The frame the daemon reads: opcode, a two-byte length covering only the payload, the increment,
// the counter name, then the tag. Pinned here because the daemon parses these exact offsets in
// fareward/src/sequence/protocol.rs.
func TestReserveSequenceFrameLayout(t *testing.T) {
	stub := startMuxDaemonStub(t)
	stub.answer = func(uint64, byte, []byte) (byte, uint16, bool) { return sequenceReplyOK, 0, true }
	stub.answerExtra = func(uint64, byte, []byte) []byte {
		return binary.BigEndian.AppendUint64(nil, 1)
	}

	if _, err := stub.client().ReserveSequence(
		context.Background(), "x12_productos_0", 5); err != nil {
		t.Fatal(err)
	}

	frame := <-stub.frames
	if frame[0] != opcodeReserveSequence {
		t.Fatalf("opcode = %#x, expected %#x", frame[0], opcodeReserveSequence)
	}
	payload := frame[1+farewardLengthPrefixSize : len(frame)-farewardAuthTagSize]
	if declared := int(binary.BigEndian.Uint16(frame[1:3])); declared != len(payload) {
		t.Fatalf("declared length %d does not match the %d-byte payload", declared, len(payload))
	}
	if increment := binary.BigEndian.Uint32(payload[0:4]); increment != 5 {
		t.Fatalf("increment = %d; want 5", increment)
	}
	if name := string(payload[4:]); name != "x12_productos_0" {
		t.Fatalf("counter name = %q; want the name verbatim", name)
	}
}

// The reserved value is the point of the call, so it has to survive the round trip exactly — a
// truncated or sign-flipped id is a valid-looking id for a different record.
func TestReserveSequenceReadsTheValueFromTheReplyTail(t *testing.T) {
	const reserved = int64(9_876_543_210)
	stub := startMuxDaemonStub(t)
	stub.answer = func(uint64, byte, []byte) (byte, uint16, bool) { return sequenceReplyOK, 0, true }
	stub.answerExtra = func(uint64, byte, []byte) []byte {
		return binary.BigEndian.AppendUint64(nil, uint64(reserved))
	}

	start, err := stub.client().ReserveSequence(context.Background(), "counter", 1)
	if err != nil {
		t.Fatal(err)
	}
	if start != reserved {
		t.Fatalf("reserved = %d; want %d", start, reserved)
	}
}

// Fails closed. The caller must not be handed a value it could mistake for a reservation, because
// the fallback it would otherwise take — the ORM's own allocator — is what mints duplicates.
func TestReserveSequenceFailsClosedOnARefusal(t *testing.T) {
	stub := startMuxDaemonStub(t)
	stub.answer = func(uint64, byte, []byte) (byte, uint16, bool) {
		// 0xFF is the daemon saying it could not answer.
		return 0xFF, 0, true
	}

	start, err := stub.client().ReserveSequence(context.Background(), "counter", 1)
	if err == nil {
		t.Fatal("an unavailable daemon must not produce a reserved value")
	}
	if !errors.Is(err, ErrSequenceUnavailable) {
		t.Fatalf("error = %v; want it to wrap ErrSequenceUnavailable", err)
	}
	if start != 0 {
		t.Fatalf("start = %d; want no value at all", start)
	}
}

// A success status with no tail, or with a non-positive value, is a daemon that disagrees with this
// client about the wire. Trusting either would write a record under an id nothing reserved.
func TestReserveSequenceRejectsAnUnusableReply(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		extra []byte
	}{
		{"no tail at all", nil},
		{"a truncated tail", []byte{0, 0, 0, 1}},
		{"a zero value", binary.BigEndian.AppendUint64(nil, 0)},
		{"a negative value", binary.BigEndian.AppendUint64(nil, uint64(^uint64(0)))},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			stub := startMuxDaemonStub(t)
			stub.answer = func(uint64, byte, []byte) (byte, uint16, bool) {
				return sequenceReplyOK, 0, true
			}
			stub.answerExtra = func(uint64, byte, []byte) []byte { return testCase.extra }

			if _, err := stub.client().ReserveSequence(
				context.Background(), "counter", 1); err == nil {
				t.Fatal("an unusable reply was accepted as a reservation")
			}
		})
	}
}

// A set carries an absolute i64 where a reservation carries a u32 count, and answers with the value
// it replaced — the caller's only record of what the counter held before a destructive repair.
func TestSetSequenceFrameLayoutAndPreviousValue(t *testing.T) {
	stub := startMuxDaemonStub(t)
	stub.answer = func(uint64, byte, []byte) (byte, uint16, bool) { return sequenceReplyOK, 0, true }
	stub.answerExtra = func(uint64, byte, []byte) []byte {
		return binary.BigEndian.AppendUint64(nil, 512)
	}

	previous, err := stub.client().SetSequence(context.Background(), "x7_ventas_0", 4)
	if err != nil {
		t.Fatal(err)
	}
	if previous != 512 {
		t.Fatalf("previous = %d; want the value the daemon replaced", previous)
	}

	frame := <-stub.frames
	if frame[0] != opcodeSetSequence {
		t.Fatalf("opcode = %#x, expected %#x", frame[0], opcodeSetSequence)
	}
	payload := frame[1+farewardLengthPrefixSize : len(frame)-farewardAuthTagSize]
	if declared := int(binary.BigEndian.Uint16(frame[1:3])); declared != len(payload) {
		t.Fatalf("declared length %d does not match the %d-byte payload", declared, len(payload))
	}
	if value := int64(binary.BigEndian.Uint64(payload[0:8])); value != 4 {
		t.Fatalf("value = %d; want 4", value)
	}
	if name := string(payload[8:]); name != "x7_ventas_0" {
		t.Fatalf("counter name = %q; want the name verbatim", name)
	}
}

// Zero is what an emptied partition resets to, so it must reach the daemon; a negative counter would
// hand out non-positive primary keys and is refused here.
func TestSetSequenceAcceptsZeroAndRejectsNegative(t *testing.T) {
	stub := startMuxDaemonStub(t)
	stub.answer = func(uint64, byte, []byte) (byte, uint16, bool) { return sequenceReplyOK, 0, true }
	stub.answerExtra = func(uint64, byte, []byte) []byte {
		return binary.BigEndian.AppendUint64(nil, 9)
	}

	if _, err := stub.client().SetSequence(context.Background(), "counter", 0); err != nil {
		t.Fatalf("a set to zero must be allowed: %v", err)
	}
	if _, err := stub.client().SetSequence(context.Background(), "counter", -1); err == nil {
		t.Fatal("a negative counter value reached the daemon instead of being refused here")
	}
}

// Refused before a frame is written: the daemon answers an oversized name by closing the
// connection, which would take every charge and lock on it along too.
func TestReserveSequenceValidatesItsArgumentsLocally(t *testing.T) {
	client := startMuxDaemonStub(t).client()
	for _, testCase := range []struct {
		name      string
		counter   string
		increment int
	}{
		{"an empty name", "", 1},
		{"a name past the ceiling", strings.Repeat("n", sequenceNameMax+1), 1},
		{"a zero increment", "counter", 0},
		{"a negative increment", "counter", -3},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := client.ReserveSequence(
				context.Background(), testCase.counter, testCase.increment); err == nil {
				t.Fatal("an invalid argument reached the daemon instead of being refused here")
			}
		})
	}
}
