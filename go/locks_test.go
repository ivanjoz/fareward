package fareward

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// muxDaemonStub speaks the real wire protocol so the client can be exercised without the Rust
// daemon: it reads whole frames, records them, and answers with whatever the test scripted.
type muxDaemonStub struct {
	listener net.Listener
	frames   chan []byte

	mu sync.Mutex
	// answer decides the reply for one request: which shape, and the body that shape carries.
	// Returning ok=false withholds the reply entirely, which is how a queued acquire is simulated.
	answer func(sequence uint64, opcode byte, payload []byte) (shape byte, body []byte, ok bool)
	// deferred holds replies the stub chose to withhold, so a test can release them later.
	deferred []deferredReply
	conns    []net.Conn
}

type deferredReply struct {
	connection net.Conn
	sequence   uint64
	shape      byte
	body       []byte
}

func startMuxDaemonStub(t *testing.T) *muxDaemonStub {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stub := &muxDaemonStub{listener: listener, frames: make(chan []byte, 32)}
	stub.answer = func(uint64, byte, []byte) (byte, []byte, bool) {
		return replyLockGranted, lockGenerationBody(7), true
	}
	go stub.serve()
	t.Cleanup(func() { listener.Close() })
	return stub
}

func (stub *muxDaemonStub) serve() {
	for {
		connection, err := stub.listener.Accept()
		if err != nil {
			return
		}
		stub.mu.Lock()
		stub.conns = append(stub.conns, connection)
		stub.mu.Unlock()
		go stub.handle(connection)
	}
}

func (stub *muxDaemonStub) handle(connection net.Conn) {
	defer connection.Close()
	if _, err := connection.Write([]byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
		return
	}
	for sequence := uint64(0); ; sequence++ {
		opcode := []byte{0}
		if _, err := io.ReadFull(connection, opcode); err != nil {
			return
		}
		// Every opcode states its own payload width, so the stub needs no table of them.
		header := make([]byte, farewardLengthPrefixSize)
		if _, err := io.ReadFull(connection, header); err != nil {
			return
		}
		declared := int(binary.BigEndian.Uint16(header))
		rest := make([]byte, declared+farewardAuthTagSize)
		if _, err := io.ReadFull(connection, rest); err != nil {
			return
		}
		body := append(header, rest...)
		payload := rest[:declared]
		stub.frames <- append(opcode, body...)

		stub.mu.Lock()
		answer := stub.answer
		stub.mu.Unlock()
		shape, body, ok := answer(sequence, opcode[0], payload)
		if !ok {
			stub.mu.Lock()
			stub.deferred = append(stub.deferred,
				deferredReply{connection, sequence, replyLockGranted, body})
			stub.mu.Unlock()
			continue
		}
		if _, err := connection.Write(makeStubReply(sequence, shape, body)); err != nil {
			return
		}
	}
}

// flushDeferred sends the replies the stub withheld earlier.
func (stub *muxDaemonStub) flushDeferred() {
	stub.mu.Lock()
	pending := stub.deferred
	stub.deferred = nil
	stub.mu.Unlock()
	for _, reply := range pending {
		reply.connection.Write(makeStubReply(reply.sequence, reply.shape, reply.body))
	}
}

func (stub *muxDaemonStub) dropConnections() {
	stub.mu.Lock()
	connections := stub.conns
	stub.conns = nil
	stub.mu.Unlock()
	for _, connection := range connections {
		connection.Close()
	}
}

// makeStubReply builds `[shape:1][correlation:u16][body…]`, the frame the daemon writes.
func makeStubReply(sequence uint64, shape byte, body []byte) []byte {
	reply := make([]byte, farewardReplyHeadSize, farewardReplyHeadSize+len(body))
	reply[0] = shape
	binary.BigEndian.PutUint16(reply[1:3], uint16(sequence))
	return append(reply, body...)
}

// lockGenerationBody is the body of a LockGranted: the generation a later release must present.
func lockGenerationBody(generation uint16) []byte {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, generation)
	return body
}

// makeStubPush builds a frame the daemon sends without being asked: no correlation, and the body
// behind the length every push carries so an unknown one can be skipped.
func makeStubPush(shape byte, body []byte) []byte {
	frame := makeStubReply(0, shape, []byte{byte(len(body))})
	return append(frame, body...)
}

// push writes a frame to every connection the stub has accepted.
func (stub *muxDaemonStub) push(frame []byte) {
	stub.mu.Lock()
	connections := append([]net.Conn(nil), stub.conns...)
	stub.mu.Unlock()
	for _, connection := range connections {
		connection.Write(frame)
	}
}

// lockLostBody names the hold a LockLost push reports.
func lockLostBody(action uint16, identifier int64) []byte {
	body := make([]byte, lockLostBodyLen)
	binary.BigEndian.PutUint16(body[0:2], action)
	binary.BigEndian.PutUint64(body[2:10], uint64(identifier))
	return body
}

func (stub *muxDaemonStub) client() *FarewardClient {
	return &FarewardClient{address: stub.listener.Addr().String(), secret: []byte("test-secret")}
}

// framePayload strips the framing a test captured off the stub — opcode, declared length, tag —
// and checks that the length header describes what actually arrived, which is the one thing a
// payload assertion cannot check for itself.
func framePayload(t *testing.T, frame []byte) []byte {
	t.Helper()
	if len(frame) < 1+farewardLengthPrefixSize+farewardAuthTagSize {
		t.Fatalf("frame % X is too short to hold its own framing", frame)
	}
	declared := int(binary.BigEndian.Uint16(frame[1 : 1+farewardLengthPrefixSize]))
	payload := frame[1+farewardLengthPrefixSize : len(frame)-farewardAuthTagSize]
	if declared != len(payload) {
		t.Fatalf("frame declares %d payload bytes and carries %d", declared, len(payload))
	}
	return payload
}

func TestAcquireAndReleaseFramesMatchTheRustVectors(t *testing.T) {
	stub := startMuxDaemonStub(t)
	client := stub.client()

	lock, err := client.Acquire(context.Background(), 7, -42, LockOptions{
		MaxWaiters: 3,
		Wait:       5000 * time.Millisecond,
		Lease:      15000 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Pinned byte for byte against service/auth.rs, which asserts the daemon accepts exactly this
	// frame. It covers the payload, the length header and the tag together, so it is the one place
	// a change to any of the three has to be acknowledged on purpose.
	expected := []byte{
		0x02, 0x00, 0x0B,
		0xD0, 0x07, 0x11, 0x2A, 0x23, 0x39, 0x88, 0x13, 0x49, 0x98, 0x3A,
		0xCD, 0xE6, 0xD2, 0x58, 0xF9, 0xB7, 0x7A, 0x2C,
	}
	if frame := <-stub.frames; string(frame) != string(expected) {
		t.Fatalf("acquire frame = % X; want % X", frame, expected)
	}

	// The release must carry the key and the generation the daemon handed back (7 here). Read
	// back through the codec rather than by offset: the payload is a colbin message now, so an
	// offset here would be asserting against this test's idea of the layout instead of the
	// encoder's.
	lock.Release()
	release := <-stub.frames
	if release[0] != opcodeLockRelease {
		t.Fatalf("release frame = % X; want a 0x03 frame", release)
	}
	var releaseFrame lockReleaseFrame
	if err := lockReleaseCodec.Unmarshal(framePayload(t, release), &releaseFrame); err != nil {
		t.Fatalf("release payload did not decode: %v", err)
	}
	if releaseFrame != (lockReleaseFrame{Action: 7, Identifier: -42, Generation: 7}) {
		t.Fatalf("release carried %+v; want action 7, identifier -42, the granted generation 7",
			releaseFrame)
	}

	// Release is idempotent: deferring it next to an early return is the normal usage.
	lock.Release()
	select {
	case extra := <-stub.frames:
		t.Fatalf("release is not idempotent, it sent % X again", extra)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestRepliesCorrelateToTheRightCallerOutOfOrder(t *testing.T) {
	// The property multiplexing rests on: a request parked in a lock queue must not stop later
	// requests from being answered, and each caller must get its own answer.
	stub := startMuxDaemonStub(t)
	stub.answer = func(sequence uint64, opcode byte, _ []byte) (byte, []byte, bool) {
		if opcode == opcodeLockAcquire {
			// Withheld, like an acquire sitting in the queue. The body is the generation it will
			// be granted with once the test releases it.
			return replyLockGranted, lockGenerationBody(11), false
		}
		// The frame that must overtake it is a charge, which has a shape of its own.
		return replyChargeAllowed, nil, true
	}
	client := stub.client()

	acquireDone := make(chan error, 1)
	go func() {
		_, err := client.Acquire(context.Background(), 1, 500, LockOptions{
			MaxWaiters: 4, Wait: 3 * time.Second, Lease: 15 * time.Second,
		})
		acquireDone <- err
	}()
	<-stub.frames // the acquire reached the stub and is now parked

	// A charge sent afterwards must be answered while the acquire still waits.
	charged := make(chan error, 1)
	go func() {
		_, chargeErr := client.Charge(context.Background(), 1, 1, 0, 2, 0, nil, false)
		charged <- chargeErr
	}()
	select {
	case err := <-charged:
		if err != nil {
			t.Fatalf("charge overtook the acquire but failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the charge was blocked behind the parked acquire")
	}
	select {
	case <-acquireDone:
		t.Fatal("the acquire should still be waiting")
	default:
	}

	stub.flushDeferred()
	if err := <-acquireDone; err != nil {
		t.Fatalf("the parked acquire never got its own reply: %v", err)
	}
}

func TestConnectionDeathFailsPendingCallersAndLosesLocks(t *testing.T) {
	stub := startMuxDaemonStub(t)
	client := stub.client()

	lock, err := client.Acquire(context.Background(), 1, 900, LockOptions{
		MaxWaiters: 1, Wait: time.Second, Lease: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	<-stub.frames

	select {
	case <-lock.Lost():
		t.Fatal("the lock is still held; Lost must not be closed yet")
	default:
	}

	// The daemon drops every lock held on a connection that dies, so the holder has to be told.
	stub.dropConnections()
	select {
	case <-lock.Lost():
	case <-time.After(2 * time.Second):
		t.Fatal("a dead connection must close Lost()")
	}
}

func TestALeaseElapsingClosesLostWithoutAnyFrame(t *testing.T) {
	// The daemon expires a hold on its own clock and has no way to push that to us, so the client
	// arms its own timer. Advisory, but without it a holder would keep believing it holds the key.
	stub := startMuxDaemonStub(t)
	client := stub.client()

	lock, err := client.Acquire(context.Background(), 1, 901, LockOptions{
		MaxWaiters: 1, Wait: time.Second, Lease: 150 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-lock.Lost():
	case <-time.After(2 * time.Second):
		t.Fatal("an elapsed lease must close Lost()")
	}
}

func TestAnAbandonedAcquireGrantedLateIsReleasedAutomatically(t *testing.T) {
	// A caller whose context is cancelled after its frame went out must not leave the key held by
	// nobody until the lease runs out.
	stub := startMuxDaemonStub(t)
	stub.answer = func(_ uint64, opcode byte, _ []byte) (byte, []byte, bool) {
		if opcode == opcodeLockAcquire {
			// Granted, but only after the caller has given up.
			return replyLockGranted, lockGenerationBody(33), false
		}
		return replyAck, nil, true
	}
	client := stub.client()

	ctx, cancel := context.WithCancel(context.Background())
	acquireDone := make(chan error, 1)
	go func() {
		_, err := client.Acquire(ctx, 1, 902, LockOptions{
			MaxWaiters: 4, Wait: 5 * time.Second, Lease: 30 * time.Second,
		})
		acquireDone <- err
	}()
	<-stub.frames
	cancel()
	if err := <-acquireDone; err == nil {
		t.Fatal("the cancelled acquire should have returned an error")
	}

	// Now the grant finally lands. The client must hand it straight back.
	stub.flushDeferred()
	select {
	case frame := <-stub.frames:
		if frame[0] != opcodeLockRelease {
			t.Fatalf("expected an automatic release, got opcode %d", frame[0])
		}
		var releaseFrame lockReleaseFrame
		if err := lockReleaseCodec.Unmarshal(framePayload(t, frame), &releaseFrame); err != nil {
			t.Fatal(err)
		}
		if releaseFrame.Generation != 33 {
			t.Fatalf("release generation = %d; want the granted 33", releaseFrame.Generation)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a lock granted after its caller gave up must be released automatically")
	}
}

func TestConcurrentSendersKeepTheSequenceInLockstep(t *testing.T) {
	// Taking a sequence and writing its frame must be atomic: interleaved writes would
	// desynchronize the tag and every later frame would fail authentication.
	stub := startMuxDaemonStub(t)
	client := stub.client()

	var waitGroup sync.WaitGroup
	for range 20 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			_, _ = client.Charge(context.Background(), 1, 1, 0, 1, 0, nil, false)
		}()
	}
	waitGroup.Wait()

	// The stub verifies nothing itself; what matters is that it could frame all 20 requests,
	// which is only possible if their bytes never interleaved.
	for range 20 {
		select {
		case frame := <-stub.frames:
			if frame[0] != opcodeChargeCredits {
				t.Fatalf("frame boundaries drifted: leading byte %d", frame[0])
			}
		case <-time.After(2 * time.Second):
			t.Fatal("not every concurrent request reached the daemon intact")
		}
	}
}

func TestAnUnreachableDaemonIsDistinguishableFromBusy(t *testing.T) {
	// A port nobody listens on: the caller must be able to tell "no answer" from "taken", since
	// that is what decides whether it fails open or closed.
	client := &FarewardClient{address: "127.0.0.1:1", secret: []byte("test-secret")}
	_, err := client.Acquire(context.Background(), 1, 5, LockOptions{Lease: time.Second})
	if !errors.Is(err, ErrLockUnavailable) {
		t.Fatalf("err = %v; want ErrLockUnavailable", err)
	}
	if errors.Is(err, ErrLockBusy) {
		t.Fatal("an unreachable daemon must never look like a busy lock")
	}
}

func TestBusyAndTimeoutRepliesBothReportBusy(t *testing.T) {
	for _, reason := range []byte{lockRefusedBusy, lockRefusedWaitTimeout} {
		stub := startMuxDaemonStub(t)
		stub.answer = func(uint64, byte, []byte) (byte, []byte, bool) {
			return replyLockRefused, []byte{reason}, true
		}
		client := stub.client()
		lock, err := client.Acquire(context.Background(), 1, 5, LockOptions{
			MaxWaiters: 1, Wait: 100 * time.Millisecond, Lease: time.Second,
		})
		if !errors.Is(err, ErrLockBusy) {
			t.Fatalf("reason %d gave err = %v; want ErrLockBusy", reason, err)
		}
		if lock != nil {
			t.Fatal("a refused acquire must not return a lock")
		}
	}
}

// A zero lease is still refused before dialing — it would expire the hold the instant it was
// granted. What is no longer refused is a long one: the wire carried uint16 milliseconds while the
// payload was a fixed fifteen bytes, which capped a lease at 65.5 s for no reason but the layout.
// A ninety-second critical section now has an honest frame.
func TestTheLeaseCeilingIsGoneButAZeroLeaseIsStillRefused(t *testing.T) {
	client := &FarewardClient{address: "127.0.0.1:1", secret: []byte("s")}
	if _, err := client.Acquire(context.Background(), 1, 5, LockOptions{Lease: 0}); err == nil {
		t.Fatal("a zero lease must be rejected before dialing")
	}
	// It never connects, so the only thing this can prove is that it got past validation and as far
	// as the dial — which is the whole claim.
	_, err := client.Acquire(context.Background(), 1, 5, LockOptions{Lease: 90 * time.Second})
	if !errors.Is(err, ErrLockUnavailable) {
		t.Fatalf("err = %v; want a 90 s lease to reach the dial rather than be refused", err)
	}

	// The ceiling that is left is what a uint32 of milliseconds can spell, which no caller reaches
	// by accident.
	_, err = client.Acquire(context.Background(), 1, 5, LockOptions{Lease: 60 * 24 * time.Hour})
	if err == nil || errors.Is(err, ErrLockUnavailable) {
		t.Fatalf("err = %v; want a validation error about the millisecond ceiling", err)
	}
}

// Phase 4: the daemon says a lease expired, rather than the client inferring it from a timer it
// started a round trip later.
func TestALockLostPushClosesTheLostChannel(t *testing.T) {
	stub := startMuxDaemonStub(t)
	client := stub.client()

	lock, err := client.Acquire(context.Background(), 7, -42, LockOptions{
		MaxWaiters: 3,
		Wait:       5000 * time.Millisecond,
		// Long enough that the local timer cannot be what closes the channel within this test —
		// only the push can. 65 535 ms is the ceiling the wire carries, which §2.7 of
		// PROTOCOL_SHAPES.md counts as a wart the colbin phase would remove.
		Lease: 60 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-lock.Lost():
		t.Fatal("the lock was lost before the daemon said anything")
	default:
	}

	stub.push(makeStubPush(replyLockLost, lockLostBody(7, -42)))

	select {
	case <-lock.Lost():
	case <-time.After(2 * time.Second):
		t.Fatal("a LockLost push did not close the Lost channel")
	}
}

// A push names one hold, so it must not end a different one — and an unknown push must cost nothing
// at all, because it states its own length and can be stepped over.
func TestAPushOnlyEndsTheLockItNames(t *testing.T) {
	stub := startMuxDaemonStub(t)
	client := stub.client()

	lock, err := client.Acquire(context.Background(), 7, 1, LockOptions{
		MaxWaiters: 3, Wait: time.Second, Lease: 60 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	stub.push(makeStubPush(replyLockLost, lockLostBody(7, 2)))
	stub.push(makeStubPush(0x9F, []byte{1, 2, 3}))

	// Round-trip something afterwards to prove the stream is still aligned.
	if _, err := client.Acquire(context.Background(), 7, 99, LockOptions{
		MaxWaiters: 3, Wait: time.Second, Lease: time.Minute,
	}); err != nil {
		t.Fatalf("the connection did not survive the pushes: %v", err)
	}

	select {
	case <-lock.Lost():
		t.Fatal("a push for another key ended this lock")
	default:
	}
}
