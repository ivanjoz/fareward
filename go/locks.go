package fareward

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ivanjoz/colbin"
)

// Ephemeral distributed locks against the Rust daemon, over the connection shared with the
// credit limiter.
//
// The problem it solves: concurrent Lambdas serving the same tenant read the same state, all
// conclude the same thing, and all write. Scylla has no transaction to stop them and the ORM has
// no LWT. A lock orders them so each one re-reads what the previous one wrote.
//
// The daemon ties a lock to the connection it was granted on, so a dead socket frees it at once
// — a killed Lambda blocks nobody. The lease we send is the daemon's own deadline on us, its
// backstop for a process that freezes without closing its socket. Both are why a lock cannot be
// released from a different connection than the one that took it.

// lockAcquireFrame and lockReleaseFrame are opcodes 0x02 and 0x03 on the wire, mirrored by
// `AcquireRequest` and `ReleaseRequest` in fareward/src/lock/protocol.rs.
//
// WaitMs and LeaseMs are uint32. They were uint16 while the payload was a fixed fifteen bytes,
// which capped a lease at 65535 ms — a ceiling nothing about locking wanted, only the layout. A
// colbin integer costs the bytes its value needs, so widening them costs nothing for the 5 s and
// 15 s the callers actually use.
type lockAcquireFrame struct {
	Action     uint16 `cb:"1"`
	Identifier int64  `cb:"2"`
	MaxWaiters uint8  `cb:"3"`
	WaitMs     uint32 `cb:"4"`
	LeaseMs    uint32 `cb:"5"`
}

type lockReleaseFrame struct {
	Action     uint16 `cb:"1"`
	Identifier int64  `cb:"2"`
	Generation uint16 `cb:"3"`
}

var (
	lockAcquireCodec = colbin.MustCodec[lockAcquireFrame]()
	lockReleaseCodec = colbin.MustCodec[lockReleaseFrame]()
)

// The action namespace itself lives in core (enums.go), not here: which features need
// serialization is a property of the application, and this package only carries the number to the
// daemon. Everything below treats an action as an opaque uint16.

var (
	// ErrLockBusy is a real answer from the daemon: the key is taken and the queue is full, or
	// our patience ran out. The caller should reject its client.
	ErrLockBusy = errors.New("lock is busy")
	// ErrLockUnavailable means we got no answer at all. Whether that is fatal is the call site's
	// decision, which is why it is a distinct error: registration fails closed on it, most other
	// callers should carry on unlocked.
	ErrLockUnavailable = ErrFarewardUnavailable
)

// Why the daemon refused, carried as the whole body of a LockRefused reply. A grant is not in this
// list: it is a shape of its own, so success and refusal no longer share a field.
const (
	lockRefusedBusy        = 1
	lockRefusedWaitTimeout = 2
	lockRefusedCapacity    = 3
	lockRefusedMisuse      = 4
)

// decodeLockGeneration reads the generation out of a LockGranted body. It is what a later release
// must present, and it is what pins that release to this grant rather than to whichever hold
// replaced it on the same key.
func decodeLockGeneration(reply muxReply) uint16 {
	if len(reply.body) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(reply.body[0:2])
}

// refusalReason reads the one byte a LockRefused carries.
func refusalReason(reply muxReply) byte {
	if len(reply.body) == 0 {
		return 0
	}
	return reply.body[0]
}

// LockOptions is the full acquire surface, reached through client.Acquire. Handlers do not build
// one: they call AcquireLock, which fills Wait and Lease with the values below.
type LockOptions struct {
	// MaxWaiters is the queue ceiling. Zero makes the call a try-lock. Callers past the ceiling
	// are refused immediately rather than parked, which is what keeps a flood from becoming a
	// denial of service against the daemon itself.
	MaxWaiters uint8
	// Wait is how long we are willing to queue. It must exceed MaxWaiters × the expected hold,
	// or waiters time out before their turn ever arrives.
	Wait time.Duration
	// Lease is the daemon's deadline on us while we hold. It must exceed the critical section,
	// and the daemon clamps it to its own configured ceiling.
	Lease time.Duration
}

// Lock is one held lock. Release is idempotent and safe to defer.
type Lock struct {
	client     *FarewardClient
	connection *muxConnection
	action     uint16
	identifier int64
	generation uint16

	releaseOnce sync.Once
	lostOnce    sync.Once
	lost        chan struct{}
	done        chan struct{}
}

// Lost closes when this lock is no longer ours: the daemon said so, the connection died, or the
// local lease timer ran out.
//
// The daemon says so first. When a lease elapses it drops the hold and pushes a LockLost frame, so
// this closes at the daemon's own deadline rather than at the local timer's — which starts a round
// trip later and is therefore always the more optimistic of the two. The timer stays as the
// backstop for the case the push cannot arrive, which is the same case the connection dying covers.
//
// It is still advisory under a partition: work inside a lock has to stay safe to run twice. What
// the push buys is that the common case — a slow critical section against a live daemon — is now
// reported rather than inferred.
func (lock *Lock) Lost() <-chan struct{} {
	return lock.lost
}

// markLost is how the connection reader reports a LockLost push.
func (lock *Lock) markLost() {
	lock.lostOnce.Do(func() { close(lock.lost) })
}

// Release hands the lock back. It must travel on the connection that took it, because that is
// what the daemon tracks; if that connection is already gone, the lock went with it.
func (lock *Lock) Release() {
	lock.releaseOnce.Do(func() {
		close(lock.done)
		lock.connection.forgetHeld(lock)
		if lock.connection.isClosed() {
			return
		}
		payload := makeLockReleasePayload(lock.action, lock.identifier, lock.generation)
		reply, err := lock.connection.exchange(
			context.Background(), lock.client.secret, opcodeLockRelease, payload,
			farewardWriteTimeout, lock.action, lock.identifier)
		if err != nil {
			logLine("lock release failed::", err)
			return
		}
		if reply.shape != replyAck {
			// A refusal here means the daemon no longer had this hold — the lease beat us to it.
			logLine("lock release refused, shape::", reply.shape, " reason::", refusalReason(reply))
		}
	})
}

// The timings every call site gets. They are not parameters because there is nothing a handler
// knows that would make it pick different ones: both are properties of this daemon and of how long
// a critical section behind it is allowed to run, not of the feature taking the lock.
//
// lockLease has to outlast the longest critical section any caller puts under a lock, or the daemon
// hands the key to the next caller while the first is still working — the exact race the lock
// exists to prevent. Sign-up is the current bound: core.SendEmail's 4s connect + 6s send plus its
// queries. Anything slower than that under a lock needs this raised, or its own lease.
//
// lockWait is deliberately shorter than that hold. Contention here is the abuse pattern, so
// refusing the extras fast is the wanted behavior; a queue that patiently absorbs a flood is doing
// the attacker's work. LockOptions remains for tests, which need to drive the edges.
const (
	lockWait  = 5 * time.Second
	lockLease = 15 * time.Second
)

// AcquireLock blocks until the key is free, the queue refuses us, or lockWait elapses.
//
// maxWaiters is the queue ceiling for this key, and the only knob a call site gets. Zero makes it a
// try-lock; callers arriving past the ceiling are refused immediately instead of parked.
func AcquireLock(
	ctx context.Context, action uint16, identifier int64, maxWaiters uint8,
) (*Lock, error) {
	client := farewardClient()
	if client == nil {
		return nil, fmt.Errorf("%w: not configured", ErrLockUnavailable)
	}
	return client.Acquire(ctx, action, identifier, LockOptions{
		MaxWaiters: maxWaiters,
		Wait:       lockWait,
		Lease:      lockLease,
	})
}

func (client *FarewardClient) Acquire(
	ctx context.Context, action uint16, identifier int64, options LockOptions,
) (*Lock, error) {
	waitMillis, err := lockDurationToMillis(options.Wait, "Wait")
	if err != nil {
		return nil, err
	}
	leaseMillis, err := lockDurationToMillis(options.Lease, "Lease")
	if err != nil {
		return nil, err
	}
	if leaseMillis == 0 {
		return nil, errors.New("LockOptions.Lease must be positive")
	}

	payload := lockAcquireCodec.Append(nil, &lockAcquireFrame{
		Action:     action,
		Identifier: identifier,
		MaxWaiters: options.MaxWaiters,
		WaitMs:     waitMillis,
		LeaseMs:    leaseMillis,
	})

	// The daemon holds the frame for up to Wait before answering, so our patience has to outlast
	// the queue, not the round trip.
	reply, connection, err := client.request(
		ctx, opcodeLockAcquire, payload, options.Wait+3*time.Second, action, identifier)
	if err != nil {
		return nil, err
	}

	switch reply.shape {
	case replyLockGranted:
		return newLock(
			client, connection, action, identifier, decodeLockGeneration(reply), options.Lease), nil
	case replyLockRefused:
		switch refusalReason(reply) {
		case lockRefusedBusy, lockRefusedWaitTimeout:
			return nil, ErrLockBusy
		case lockRefusedCapacity:
			return nil, fmt.Errorf("%w: daemon at capacity", ErrLockUnavailable)
		}
		return nil, fmt.Errorf("%w: refused with reason %d", ErrLockUnavailable, refusalReason(reply))
	default:
		return nil, fmt.Errorf("%w: acquire answered with shape 0x%02X",
			ErrLockUnavailable, reply.shape)
	}
}

func newLock(
	client *FarewardClient, connection *muxConnection,
	action uint16, identifier int64, generation uint16, lease time.Duration,
) *Lock {
	lock := &Lock{
		client:     client,
		connection: connection,
		action:     action,
		identifier: identifier,
		generation: generation,
		lost:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	// Filed before the watcher starts: a lease this short could elapse on the daemon before this
	// function returns, and a push that arrived first would otherwise find nothing to mark.
	connection.registerHeld(lock)

	// Watches for the two ways this hold can end that no push will report. Exits as soon as the
	// lock is released normally, so it costs nothing in the common case.
	go func() {
		timer := time.NewTimer(lease)
		defer timer.Stop()
		select {
		case <-lock.done:
			return
		case <-connection.closed:
		case <-timer.C:
		}
		lock.markLost()
	}()
	return lock
}

func makeLockReleasePayload(action uint16, identifier int64, generation uint16) []byte {
	return lockReleaseCodec.Append(nil, &lockReleaseFrame{
		Action:     action,
		Identifier: identifier,
		Generation: generation,
	})
}

// lockDurationToMillis enforces the uint32 milliseconds the wire carries — 49 days, which is a
// ceiling no caller can reach by accident. The daemon clamps a lease to its own configured maximum
// anyway, so this only has to refuse what cannot be spelled.
func lockDurationToMillis(value time.Duration, name string) (uint32, error) {
	if value < 0 {
		return 0, fmt.Errorf("LockOptions.%s cannot be negative", name)
	}
	millis := value.Milliseconds()
	if millis > int64(^uint32(0)) {
		return 0, fmt.Errorf("LockOptions.%s exceeds the %d ms the protocol carries",
			name, ^uint32(0))
	}
	return uint32(millis), nil
}
