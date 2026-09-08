package fareward

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Autoincrement and write-sequence reservation against the Rust daemon, over the connection shared
// with the credit limiter and the lock service.
//
// The problem it solves: the ORM's own allocator reads a counter and then increments it, with
// nothing in between, so two concurrent writers read the same value and mint the same id. Scylla's
// counter type makes the increment atomic but will not tell you the result of your own increment,
// so the read is always a guess about who else is in flight. Moving the reservation into a single
// process removes the guess.
//
// The daemon hands out values from in-memory blocks it has already claimed durably, so the common
// call costs no database round trip at all. What it requires in exchange is exclusivity: while this
// is in use, nothing else may advance those counters, or the daemon's claimed range and the other
// writer's will overlap.

const (
	sequenceIncrementSize = 4
	sequenceValueSize     = 8
	// Mirrors SEQUENCE_NAME_MAX in fareward/src/sequence/protocol.rs. The daemon refuses a longer
	// name by closing the connection, so the check happens here first with a usable error.
	sequenceNameMax = 128
	// Both replies carry exactly one int64: the reserved value, or the value a set replaced.
	sequenceReplyExtraSize = 8

	sequenceReplyOK      = 0
	sequenceReplyInvalid = 1
)

// A reservation is a single round trip to a daemon that usually answers from memory, so this only
// has to outlast a block miss going to ScyllaDB.
const sequenceReserveTimeout = 5 * time.Second

// ErrSequenceUnavailable means no value was reserved. It is deliberately fatal to the caller's
// write: the alternative — falling back to the ORM's own allocator — is exactly what mints a
// duplicate id, because the daemon may already own a range that allocator knows nothing about.
var ErrSequenceUnavailable = ErrFarewardUnavailable

// ReserveSequence reserves `increment` consecutive values on the counter called `name` and returns
// the first of them, which is what genix-orm's GetCounter returns for the same arguments.
//
// `name` is the ORM's own counter name, travelling verbatim: the daemon writes it into the same
// `sequences` row the ORM would have written, so the counters stay readable by name from CQL,
// from deploy.go's ResetCounter, and from a person debugging one.
func ReserveSequence(ctx context.Context, name string, increment int) (int64, error) {
	client := farewardClient()
	if client == nil {
		return 0, fmt.Errorf("%w: not configured", ErrSequenceUnavailable)
	}
	return client.ReserveSequence(ctx, name, increment)
}

func (client *FarewardClient) ReserveSequence(
	ctx context.Context, name string, increment int,
) (int64, error) {
	if err := checkCounterName(name); err != nil {
		return 0, err
	}
	if increment < 1 {
		return 0, fmt.Errorf("ReserveSequence needs a positive increment, got %d", increment)
	}
	if increment > int(^uint32(0)) {
		return 0, fmt.Errorf("increment %d exceeds the uint32 the protocol carries", increment)
	}

	// The increment leads so the name can be the payload's tail: the frame's own length header
	// already bounds it, so it needs no length of its own.
	payload := make([]byte, sequenceIncrementSize, sequenceIncrementSize+len(name))
	binary.BigEndian.PutUint32(payload[0:sequenceIncrementSize], uint32(increment))
	payload = append(payload, name...)

	// request retries once on a connection that turned out to be dead. That is safe here even
	// though a reservation is not idempotent: a replay claims a second range and abandons the
	// first, which is a gap in the sequence and never a reused value. Gaps are already the
	// accepted cost of the daemon's block allocation.
	reply, _, err := client.request(
		ctx, opcodeReserveSequence, payload, sequenceReserveTimeout, 0, 0)
	if err != nil {
		return 0, err
	}

	reserved, err := decodeSequenceReply(reply, name)
	if err != nil {
		return 0, err
	}
	// An id has to be positive: it becomes a primary key, and the ORM treats anything at or below
	// zero as "not yet assigned", so a non-positive value here would loop back into another
	// reservation on the next write. A set has no such rule — zero is a legitimate previous value.
	if reserved <= 0 {
		return 0, fmt.Errorf("%w: daemon reserved a non-positive value %d",
			ErrSequenceUnavailable, reserved)
	}
	return reserved, nil
}

// SetSequence moves a counter to an absolute value and returns what it held before.
//
// This is the repair path — restoring a backup, realigning a counter with the rows that survived —
// and it must come through the daemon rather than writing the row directly. The daemon may be
// serving a block of ids it derived from the old value; only it can drop that block in the same
// breath as moving the counter. Writing the row behind its back leaves it handing out values from a
// range that no longer means anything, and the next block it claims then repeats them.
func SetSequence(ctx context.Context, name string, value int64) (int64, error) {
	client := farewardClient()
	if client == nil {
		return 0, fmt.Errorf("%w: not configured", ErrSequenceUnavailable)
	}
	return client.SetSequence(ctx, name, value)
}

func (client *FarewardClient) SetSequence(
	ctx context.Context, name string, value int64,
) (int64, error) {
	if err := checkCounterName(name); err != nil {
		return 0, err
	}
	// Zero is legitimate — an emptied partition resets to it — but a negative counter would hand
	// out non-positive primary keys.
	if value < 0 {
		return 0, fmt.Errorf("SetSequence cannot set counter %q to a negative value %d", name, value)
	}

	payload := make([]byte, sequenceValueSize, sequenceValueSize+len(name))
	binary.BigEndian.PutUint64(payload[0:sequenceValueSize], uint64(value))
	payload = append(payload, name...)

	// requestOnce, not request: a set is an absolute assignment, so a replay would be harmless in
	// itself — but the reply carries the value it replaced, and a retry would report the value the
	// first attempt already wrote. That is the one record of what the counter held before a
	// destructive repair, so an ambiguous disconnect is returned rather than papered over.
	reply, err := client.requestOnce(ctx, opcodeSetSequence, payload, sequenceReserveTimeout)
	if err != nil {
		return 0, err
	}
	return decodeSequenceReply(reply, name)
}

func checkCounterName(name string) error {
	if name == "" {
		return errors.New("a counter name is required")
	}
	if len(name) > sequenceNameMax {
		return fmt.Errorf("counter name %q is %d bytes, over the %d the protocol carries",
			name, len(name), sequenceNameMax)
	}
	return nil
}

// decodeSequenceReply reads the int64 both sequence opcodes answer with, refusing anything that
// would let a caller act on a value the daemon did not actually send.
func decodeSequenceReply(reply muxReply, name string) (int64, error) {
	switch reply.status {
	case sequenceReplyOK:
		if len(reply.extra) != sequenceReplyExtraSize {
			return 0, fmt.Errorf("%w: sequence value is %d bytes, expected %d",
				ErrSequenceUnavailable, len(reply.extra), sequenceReplyExtraSize)
		}
		return int64(binary.BigEndian.Uint64(reply.extra)), nil
	case sequenceReplyInvalid:
		return 0, fmt.Errorf("fareward refused the request for counter %q as malformed", name)
	default:
		return 0, fmt.Errorf("%w: unexpected reply status %d", ErrSequenceUnavailable, reply.status)
	}
}
