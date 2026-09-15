package fareward

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ivanjoz/fareward/go/siphash"
)

// One multiplexed TCP connection to the fareward daemon, shared by every operation in this
// process: credit charges and locks alike.
//
// Requests travel in order and carry a sequence that both sides advance in lockstep for the
// frame tag. Replies do not: an acquire can sit in a lock queue for seconds while charges sent
// after it are answered immediately. Each reply therefore echoes the low 16 bits of its
// request's sequence, and a single reader goroutine uses that to hand the answer to the right
// caller. Nothing extra travels on the wire to make this work — the sequence already existed.
//
// The one hard rule: taking a sequence and writing its frame must be atomic. Two goroutines
// taking 5 and 6 but writing 6, 5 would desynchronize the tag and every later frame would fail.
// That is what writeMu guards, and it is held for a socket write, never for a round trip.

const (
	farewardNonceSize   = 8
	farewardAuthTagSize = 8
	// Every reply starts with [shape:1][correlation:u16]. What follows is the body the shape names,
	// which is nothing at all for four of the eleven shapes.
	farewardReplyHeadSize = 3
	// Width of the length header every opcode carries between the opcode and its payload.
	// Mirrors LENGTH_PREFIX_SIZE in fareward/src/service/protocol.rs.
	farewardLengthPrefixSize = 2
	// Names the framing of the whole port, request and reply, and is bumped on every wire change
	// so a mismatched peer fails at the first frame instead of misreading bytes.
	// `:v7` renamed the string itself from `genix-server-utils` to `fareward` and `:v8` replaced
	// truncated HMAC-SHA256 with SipHash-2-4. Neither changed a frame's layout, but each
	// invalidates every tag a peer on the old string produces, so both spend a bump rather than
	// leaving two incompatible protocols under one name. `:v9` grew a length-prefixed reply tail.
	// `:v10` gave every reply a shape in byte 0 and retired the status/detail pair, whose meaning
	// depended on which request the correlation belonged to — a peer on `:v9` would read the shape
	// as half a correlation and be wrong about every frame after it.
	// `:v11` moved six of the eight request payloads onto colbin and length-prefixed all of them,
	// so a peer on `:v10` would read a length header as a payload's first two bytes.
	// Mirrored byte for byte by DOMAIN in fareward/src/service/auth.rs; backend and daemon must
	// cross this boundary in a single deploy.
	farewardAuthDomain = "fareward:v11"

	opcodeChargeCredits = byte(0x01)
	opcodeLockAcquire   = byte(0x02)
	opcodeLockRelease   = byte(0x03)
	// opcodeLogRequest is one of the two opcodes the daemon does not answer: it carries a log
	// record, and making a response wait for an acknowledgement that a log was stored would put the
	// daemon's latency on the critical path of every request in the system.
	opcodeLogRequest          = byte(0x04)
	opcodeMutateCompanyBudget = byte(0x05)
	// opcodeInvalidateUserAccess is the second unanswered opcode: the TTL on the daemon's grant
	// cache is the backstop if it is lost, so a user save does not wait for an acknowledgement.
	opcodeInvalidateUserAccess = byte(0x06)
	// The two sequence opcodes are the only request payloads that are not colbin messages. They are
	// a scalar and a counter name, and PROTOCOL_SHAPES.md §4.3 is why they stay hand-rolled: the
	// reserve path is the ORM's insert path, and the shape has no room to grow.
	opcodeReserveSequence = byte(0x07)
	opcodeSetSequence     = byte(0x08)

	// Frames are tiny and the daemon is on loopback or a private network, so a write that cannot
	// complete in this long means the connection is gone.
	farewardWriteTimeout = 5 * time.Second
	farewardDialTimeout  = 2 * time.Second
)

// logLine is how this package reports anything: it cannot import core, because core needs
// CreditLimitExceeded for its HTTP error mapping and that would be an import cycle. main pushes
// core.Log in at startup, the same way text_search receives its configuration.
var logLine = func(args ...any) {}

// SetLogger installs the process logger. Called once from main, before any request is served.
func SetLogger(logger func(args ...any)) {
	if logger != nil {
		logLine = logger
	}
}

// ErrFarewardUnavailable means no answer arrived. Callers distinguish it from a real verdict:
// a charge treats it as permission to proceed, sign-up treats it as a reason to refuse.
var ErrFarewardUnavailable = errors.New("fareward service is unavailable")

// Reply shapes. Byte 0 of every reply names the outcome, which is what lets the reader parse a
// frame without first remembering what was asked. Mirrors ReplyShape in
// fareward/src/service/protocol.rs.
const (
	replyChargeAllowed         = byte(0x01)
	replyChargeGranted         = byte(0x02)
	replyChargeCreditViolation = byte(0x03)
	replyChargeAccessDenied    = byte(0x04)
	replyLockGranted           = byte(0x05)
	replyLockRefused           = byte(0x06)
	replyAck                   = byte(0x07)
	replyBudgetRefused         = byte(0x08)
	replySequenceValue         = byte(0x09)
	replySequenceInvalid       = byte(0x0A)
	// replyUnavailable is "I could not answer". Every operation applies its own policy to it:
	// credits fail closed, a sequence fails the write, lock call sites decide individually.
	replyUnavailable = byte(0x7F)
	// replyLockLost and anything above it is a push: a frame the daemon sends without being asked,
	// which carries no correlation and is routed on its shape alone. Every push is [len:u8][body],
	// so a push this client predates can be stepped over instead of killing the connection.
	replyLockLost   = byte(0x80)
	replyPushFloor  = byte(0x80)
	lockLostBodyLen = 10
)

// replyBodySize is how many bytes follow the head, or -1 when the shape states its own length.
// Mirrors ReplyShape::body_size; a disagreement here desynchronizes every reply after the first.
func replyBodySize(shape byte) (int, bool) {
	switch shape {
	case replyChargeAllowed, replyAck, replySequenceInvalid, replyUnavailable:
		return 0, true
	case replyChargeCreditViolation, replyChargeAccessDenied, replyLockRefused, replyBudgetRefused:
		return 1, true
	case replyLockGranted:
		return 2, true
	case replySequenceValue:
		return sequenceReplyExtraSize, true
	case replyChargeGranted:
		// Two masks, a sub-byte count, and that many sub bytes.
		return -1, true
	default:
		return 0, false
	}
}

type muxReply struct {
	// shape is the outcome. Every call site switches on it instead of decoding a status byte whose
	// meaning depended on the request it answered.
	shape byte
	// body is what the shape carries, empty for the four shapes that carry nothing.
	body []byte
}

type pendingRequest struct {
	reply chan muxReply
	// abandoned marks a caller that stopped waiting. The entry stays in the map so a late reply
	// can still be handled: an acquire granted after its caller gave up has to be released, or
	// the key stays locked with nobody holding it.
	abandoned  bool
	opcode     byte
	action     uint16
	identifier int64
}

// heldKey identifies one lock on one connection, which is what a LockLost push names.
type heldKey struct {
	action     uint16
	identifier int64
}

type muxConnection struct {
	conn  net.Conn
	nonce [farewardNonceSize]byte

	writeMu  sync.Mutex
	sequence uint64

	pendingMu sync.Mutex
	pending   map[uint16]*pendingRequest

	// heldMu guards the locks granted on this connection, so a LockLost push can find the Lock it
	// names. Registered when a grant arrives and dropped on release, which keeps the map the size
	// of what this process actually holds.
	heldMu sync.Mutex
	held   map[heldKey]*Lock

	closed    chan struct{}
	closeOnce sync.Once
}

type FarewardClient struct {
	address string
	secret  []byte
	mu      sync.Mutex
	current *muxConnection
}

var (
	configuredFarewardMu sync.RWMutex
	configuredFareward   *FarewardClient
)

// ConfigureFareward installs the process-wide client. One address, one secret, one connection
// for both the credit limiter and the lock service — the opcode decides which.
func ConfigureFareward(address, secret string) error {
	address = strings.TrimSpace(address)
	if address == "" {
		return errors.New("fareward is required by the fareward client")
	}
	if strings.TrimSpace(secret) == "" {
		return errors.New("internal_apikey is required by the fareward client")
	}
	client := &FarewardClient{address: address, secret: []byte(secret)}
	configuredFarewardMu.Lock()
	previous := configuredFareward
	configuredFareward = client
	configuredFarewardMu.Unlock()
	if previous != nil {
		previous.Close()
	}
	return nil
}

func farewardClient() *FarewardClient {
	configuredFarewardMu.RLock()
	defer configuredFarewardMu.RUnlock()
	return configuredFareward
}

// Close drops the current connection, which releases every lock held on it.
func (client *FarewardClient) Close() {
	client.mu.Lock()
	connection := client.current
	client.current = nil
	client.mu.Unlock()
	if connection != nil {
		connection.fail(errors.New("client closed"))
	}
}

// request sends one frame and waits for its reply, retrying once on a connection that turned out
// to be dead. It returns the connection used, because a lock must be released on the same one.
func (client *FarewardClient) request(
	ctx context.Context, opcode byte, payload []byte, wait time.Duration,
	action uint16, identifier int64,
) (muxReply, *muxConnection, error) {
	var lastError error
	for attempt := range 2 {
		connection, reused, err := client.connection(ctx)
		if err != nil {
			return muxReply{}, nil, fmt.Errorf("%w: connect: %v", ErrFarewardUnavailable, err)
		}
		reply, err := connection.exchange(
			ctx, client.secret, opcode, payload, wait, action, identifier)
		if err == nil {
			return reply, connection, nil
		}
		lastError = err
		// A pooled connection the daemon closed while idle looks exactly like this. Retrying is
		// safe for an acquire too: ownership is tied to the connection, so anything granted on a
		// dead one was already released with it.
		if reused && attempt == 0 && !errors.Is(err, context.Canceled) &&
			!errors.Is(err, context.DeadlineExceeded) {
			continue
		}
		break
	}
	return muxReply{}, nil, fmt.Errorf("%w: %v", ErrFarewardUnavailable, lastError)
}

// requestOnce avoids replaying non-idempotent operations such as increasing a credit balance.
// An ambiguous disconnect is returned to the caller, which must re-read durable state.
func (client *FarewardClient) requestOnce(
	ctx context.Context, opcode byte, payload []byte, wait time.Duration,
) (muxReply, error) {
	connection, _, err := client.connection(ctx)
	if err != nil {
		return muxReply{}, fmt.Errorf("%w: connect: %v", ErrFarewardUnavailable, err)
	}
	reply, err := connection.exchange(ctx, client.secret, opcode, payload, wait, 0, 0)
	if err != nil {
		return muxReply{}, fmt.Errorf("%w: %v", ErrFarewardUnavailable, err)
	}
	return reply, nil
}

// send writes one frame the daemon will not answer, and returns as soon as the bytes are in the
// socket.
//
// No pending entry is registered, which is the point: the reader would otherwise log every
// unmatched reply, and a caller would be parked waiting for one that never comes. The frame
// sequence still advances under writeMu in lockstep with the daemon's, because that is what the
// tag is bound to — a fire-and-forget frame that skipped the sequence would invalidate every
// frame after it on this connection.
//
// One retry, for the same reason a request gets one: a pooled connection the daemon closed while
// idle is indistinguishable from a live one until the write fails.
func (client *FarewardClient) send(ctx context.Context, opcode byte, payload []byte) error {
	var lastError error
	for attempt := range 2 {
		connection, reused, err := client.connection(ctx)
		if err != nil {
			return fmt.Errorf("%w: connect: %v", ErrFarewardUnavailable, err)
		}
		if err := connection.write(client.secret, opcode, payload); err == nil {
			return nil
		} else {
			lastError = err
		}
		if reused && attempt == 0 {
			continue
		}
		break
	}
	return fmt.Errorf("%w: %v", ErrFarewardUnavailable, lastError)
}

// write builds and writes one length-prefixed frame under the sequence lock.
func (connection *muxConnection) write(secret []byte, opcode byte, payload []byte) error {
	connection.writeMu.Lock()
	if connection.sequence == ^uint64(0) {
		connection.writeMu.Unlock()
		connection.fail(errors.New("frame sequence exhausted"))
		return errors.New("frame sequence exhausted")
	}
	sequence := connection.sequence
	connection.sequence++

	frame := buildFarewardFrame(secret, &connection.nonce, sequence, opcode, payload)
	writeErr := connection.conn.SetWriteDeadline(time.Now().Add(farewardWriteTimeout))
	if writeErr == nil {
		writeErr = writeCompleteFrame(connection.conn, frame)
	}
	connection.writeMu.Unlock()

	if writeErr != nil {
		connection.fail(writeErr)
	}
	return writeErr
}

// connection returns the shared connection, dialing one if none is healthy, and reports whether
// it was already open.
func (client *FarewardClient) connection(ctx context.Context) (*muxConnection, bool, error) {
	// The dial happens under the lock on purpose. Releasing it first lets every concurrent
	// caller open its own socket and then throw all but one away — a burst of six requests on a
	// cold client opened six connections. Waiting behind one dial is what they would have spent
	// anyway, and it is bounded by farewardDialTimeout.
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.current != nil && !client.current.isClosed() {
		return client.current, true, nil
	}

	dialed, err := client.dial(ctx)
	if err != nil {
		return nil, false, err
	}
	client.current = dialed
	go dialed.readLoop(client)
	return dialed, false, nil
}

func (client *FarewardClient) dial(ctx context.Context) (*muxConnection, error) {
	dialer := net.Dialer{Timeout: farewardDialTimeout, KeepAlive: 30 * time.Second}
	socket, err := dialer.DialContext(ctx, "tcp", client.address)
	if err != nil {
		return nil, err
	}
	connection := &muxConnection{
		conn:    socket,
		pending: map[uint16]*pendingRequest{},
		held:    map[heldKey]*Lock{},
		closed:  make(chan struct{}),
	}
	if err := socket.SetReadDeadline(time.Now().Add(farewardDialTimeout)); err != nil {
		socket.Close()
		return nil, err
	}
	if _, err := io.ReadFull(socket, connection.nonce[:]); err != nil {
		socket.Close()
		return nil, fmt.Errorf("read server nonce: %w", err)
	}
	// Clear it again: from here the reader blocks indefinitely and per-request deadlines are
	// enforced by the callers, since one socket now carries many requests with different ones.
	if err := socket.SetReadDeadline(time.Time{}); err != nil {
		socket.Close()
		return nil, err
	}
	return connection, nil
}

func (connection *muxConnection) exchange(
	ctx context.Context, secret []byte, opcode byte, payload []byte, wait time.Duration,
	action uint16, identifier int64,
) (muxReply, error) {
	pending := &pendingRequest{
		// Buffered, so the reader never blocks handing over an answer nobody is waiting for yet.
		reply:      make(chan muxReply, 1),
		opcode:     opcode,
		action:     action,
		identifier: identifier,
	}

	connection.writeMu.Lock()
	if connection.sequence == ^uint64(0) {
		connection.writeMu.Unlock()
		connection.fail(errors.New("frame sequence exhausted"))
		return muxReply{}, errors.New("frame sequence exhausted")
	}
	sequence := connection.sequence
	correlation := uint16(sequence)
	connection.pendingMu.Lock()
	if _, taken := connection.pending[correlation]; taken {
		connection.pendingMu.Unlock()
		connection.writeMu.Unlock()
		return muxReply{}, errors.New("too many requests in flight on one connection")
	}
	connection.pending[correlation] = pending
	connection.pendingMu.Unlock()
	connection.sequence++

	frame := buildFarewardFrame(secret, &connection.nonce, sequence, opcode, payload)
	writeErr := connection.conn.SetWriteDeadline(time.Now().Add(farewardWriteTimeout))
	if writeErr == nil {
		writeErr = writeCompleteFrame(connection.conn, frame)
	}
	connection.writeMu.Unlock()

	if writeErr != nil {
		connection.forget(correlation)
		connection.fail(writeErr)
		return muxReply{}, writeErr
	}

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case reply := <-pending.reply:
		return reply, nil
	case <-connection.closed:
		connection.forget(correlation)
		return muxReply{}, errors.New("connection closed while waiting for a reply")
	case <-ctx.Done():
		connection.abandon(correlation)
		return muxReply{}, ctx.Err()
	case <-timer.C:
		connection.abandon(correlation)
		return muxReply{}, errors.New("timed out waiting for a reply")
	}
}

// readLoop is the only reader of this socket. It dispatches by correlation, which is what lets
// several callers share the connection.
func (connection *muxConnection) readLoop(client *FarewardClient) {
	for {
		head := [farewardReplyHeadSize]byte{}
		if _, err := io.ReadFull(connection.conn, head[:]); err != nil {
			connection.fail(err)
			return
		}
		answer := muxReply{shape: head[0]}
		correlation := binary.BigEndian.Uint16(head[1:3])

		// The body is read before anything is dispatched, because a stream left unread mid-frame
		// desynchronizes every reply after it — including the ones nobody is waiting for.
		//
		// A push says how long it is, so an unknown one costs nothing: it is consumed and dropped.
		// An unknown *reply* is fatal, because without a width there is no way to find where the
		// next frame starts.
		if answer.shape >= replyPushFloor {
			if err := connection.readPush(answer.shape); err != nil {
				connection.fail(err)
				return
			}
			continue
		}
		size, known := replyBodySize(answer.shape)
		if !known {
			connection.fail(fmt.Errorf(
				"fareward sent reply shape 0x%02X, which this client does not know", answer.shape))
			return
		}
		if size < 0 {
			// The one variable body: two masks and the sub-byte count that follows them.
			answer.body = make([]byte, 3)
			if _, err := io.ReadFull(connection.conn, answer.body); err != nil {
				connection.fail(err)
				return
			}
			if subBytes := int(answer.body[2]); subBytes > 0 {
				tail := make([]byte, subBytes)
				if _, err := io.ReadFull(connection.conn, tail); err != nil {
					connection.fail(err)
					return
				}
				answer.body = append(answer.body, tail...)
			}
		} else if size > 0 {
			answer.body = make([]byte, size)
			if _, err := io.ReadFull(connection.conn, answer.body); err != nil {
				connection.fail(err)
				return
			}
		}

		connection.pendingMu.Lock()
		request, known := connection.pending[correlation]
		if known {
			delete(connection.pending, correlation)
		}
		connection.pendingMu.Unlock()

		if !known {
			// Nobody is waiting for this. Not fatal — the caller may have been abandoned and
			// already cleaned up — but it should never happen in a healthy stream.
			logLine("fareward reply with no matching request::", correlation)
			continue
		}
		if request.abandoned {
			// The caller gave up, but the daemon may still have granted the lock. Hand it back
			// straight away instead of leaving the key held by nobody until its lease expires.
			if request.opcode == opcodeLockAcquire && answer.shape == replyLockGranted {
				go client.releaseAbandoned(
					connection, request.action, request.identifier, decodeLockGeneration(answer))
			}
			continue
		}
		request.reply <- answer
	}
}

// readPush consumes one push and acts on it. A push answers nothing, so it never reaches the
// pending map — and it states its own length, so one this client does not know is skipped rather
// than fatal.
func (connection *muxConnection) readPush(shape byte) error {
	length := [1]byte{}
	if _, err := io.ReadFull(connection.conn, length[:]); err != nil {
		return err
	}
	body := make([]byte, length[0])
	if _, err := io.ReadFull(connection.conn, body); err != nil {
		return err
	}
	connection.handlePush(muxReply{shape: shape, body: body})
	return nil
}

// handlePush acts on a frame the daemon sent without being asked.
//
// Only one shape reaches here today: the daemon noticed a lease elapse and dropped a hold this
// process still believes it owns. Telling the Lock makes its Lost channel authoritative at the
// daemon's own deadline instead of a round trip later, which is when the client's timer starts.
func (connection *muxConnection) handlePush(answer muxReply) {
	if answer.shape != replyLockLost {
		// Already consumed by readPush, so the stream is still aligned: a newer daemon may simply
		// push something this client predates.
		logLine("fareward push with an unknown shape::", answer.shape)
		return
	}
	if len(answer.body) < lockLostBodyLen {
		logLine("fareward sent a short LockLost push::", len(answer.body))
		return
	}
	action := binary.BigEndian.Uint16(answer.body[0:2])
	identifier := int64(binary.BigEndian.Uint64(answer.body[2:10]))
	logLine("fareward reports a lease expired::", action, identifier)

	key := heldKey{action: action, identifier: identifier}
	connection.heldMu.Lock()
	lock := connection.held[key]
	// Dropped here rather than waiting for a Release that may never come: the daemon has already
	// let this hold go, so the entry can only keep a dead Lock alive for the life of the socket.
	delete(connection.held, key)
	connection.heldMu.Unlock()
	if lock != nil {
		lock.markLost()
	}
}

// registerHeld files a granted lock so a LockLost push can find it.
func (connection *muxConnection) registerHeld(lock *Lock) {
	connection.heldMu.Lock()
	connection.held[heldKey{action: lock.action, identifier: lock.identifier}] = lock
	connection.heldMu.Unlock()
}

func (connection *muxConnection) forgetHeld(lock *Lock) {
	connection.heldMu.Lock()
	delete(connection.held, heldKey{action: lock.action, identifier: lock.identifier})
	connection.heldMu.Unlock()
}

// releaseAbandoned returns a lock that was granted to a caller which had already stopped waiting.
func (client *FarewardClient) releaseAbandoned(
	connection *muxConnection, action uint16, identifier int64, generation uint16,
) {
	logLine("fareward releasing a lock granted after its caller gave up::", action, identifier)
	payload := makeLockReleasePayload(action, identifier, generation)
	_, err := connection.exchange(
		context.Background(), client.secret, opcodeLockRelease, payload,
		farewardWriteTimeout, action, identifier)
	if err != nil {
		// Not recoverable, and not fatal: the lease is the backstop.
		logLine("fareward could not release an abandoned lock::", err)
	}
}

func (connection *muxConnection) forget(correlation uint16) {
	connection.pendingMu.Lock()
	delete(connection.pending, correlation)
	connection.pendingMu.Unlock()
}

func (connection *muxConnection) abandon(correlation uint16) {
	connection.pendingMu.Lock()
	if request, known := connection.pending[correlation]; known {
		request.abandoned = true
	}
	connection.pendingMu.Unlock()
}

// fail tears the connection down once and wakes everyone waiting on it. A dead socket must never
// leave a goroutine blocked forever, and it also means the daemon dropped every lock held here.
func (connection *muxConnection) fail(cause error) {
	connection.closeOnce.Do(func() {
		connection.conn.Close()
		close(connection.closed)
		logLine("fareward connection closed::", cause)
	})
}

func (connection *muxConnection) isClosed() bool {
	select {
	case <-connection.closed:
		return true
	default:
		return false
	}
}

// buildFarewardFrame lays out one frame: the opcode, the payload's length, the payload, and the
// tag over all three.
//
// Every opcode is length-prefixed. There used to be a second, fixed-width form for the operations
// whose payload the opcode alone described, but no such operation is left: six of the eight are
// colbin messages that write only the bytes a value needs, and the other two carry a counter name.
// The tag covers the length header too, so a peer cannot make the daemon buffer a different amount
// than the one that was signed.
//
// Mirrors the frame reader in fareward/src/service/protocol.rs.
func buildFarewardFrame(
	secret []byte, nonce *[farewardNonceSize]byte, sequence uint64, opcode byte, payload []byte,
) []byte {
	frame := make([]byte, 0, 1+farewardLengthPrefixSize+len(payload)+farewardAuthTagSize)
	frame = append(frame, opcode)
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
	frame = append(frame, payload...)
	return append(frame, farewardAuthTag(secret, nonce, sequence, frame)...)
}

// farewardAuthTag signs one frame for one position in one connection's stream. Binding the
// tag to both the server nonce and the frame sequence is what stops a captured frame from being
// replayed, on this connection or any other.
//
// SipHash-2-4 is a 64-bit function, so the tag is the whole output rather than the front of a
// digest, written big-endian like every other fixed-width field on this wire. Exact mirror of
// fareward's src/service/auth.rs.
func farewardAuthTag(
	secret []byte, nonce *[farewardNonceSize]byte, sequence uint64, signed []byte,
) []byte {
	hasher := siphash.New(siphash.DeriveKey(secret))
	hasher.WriteString(farewardAuthDomain)
	hasher.Write(nonce[:])
	sequenceBytes := [8]byte{}
	binary.BigEndian.PutUint64(sequenceBytes[:], sequence)
	hasher.Write(sequenceBytes[:])
	hasher.Write(signed)
	return binary.BigEndian.AppendUint64(make([]byte, 0, farewardAuthTagSize), hasher.Sum64())
}

func writeCompleteFrame(connection net.Conn, frame []byte) error {
	for len(frame) > 0 {
		written, err := connection.Write(frame)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		frame = frame[written:]
	}
	return nil
}
