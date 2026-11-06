package fareward

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// A "unix:" address must reach the daemon over its Unix domain socket and speak the exact same
// protocol as TCP: handshake nonce, signed frames, correlated replies.
func TestUnixSocketAddressDialsTheDomainSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "fareward.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	stub := &muxDaemonStub{listener: listener, frames: make(chan []byte, 32)}
	stub.answer = func(uint64, byte, []byte) (byte, []byte, bool) {
		return replyLockGranted, lockGenerationBody(7), true
	}
	go stub.serve()
	t.Cleanup(func() { listener.Close() })

	client := &FarewardClient{address: "unix:" + socketPath, secret: []byte("test-secret")}
	lock, err := client.Acquire(context.Background(), 7, -42, LockOptions{
		Wait:  time.Second,
		Lease: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("acquire over the unix socket: %v", err)
	}
	<-stub.frames
	lock.Release()
}
