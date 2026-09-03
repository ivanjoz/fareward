// Package siphash implements SipHash-2-4, the keyed pseudo-random function behind the two internal
// tags between this project's Go processes and the fareward daemon: the raw-TCP frame tag and the
// bridge's X-Bridge-Auth header. The browser session token deliberately does not use it — a
// user-held credential gets a 128-bit keyed-BLAKE2s tag instead (core.ComputeUsuarioTokenHash).
//
// It is a keyed PRF for short messages, not a general-purpose hash. Nothing here may be used as a
// public digest or relied on for collision resistance without the key — every call site
// authenticates with a shared secret and publishes nothing.
//
// This is the mirror of fareward's src/siphash.rs, byte for byte, down to the key derivation.
// Both are pinned against the reference vectors from the SipHash paper, so they agree for a
// stronger reason than a shared fixture. Written here rather than imported because this module
// takes no dependencies beyond the standard library.
package siphash

import (
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
)

// The four constants SipHash initializes its state from: "somepseudorandomlygeneratedbytes".
const (
	init0 = 0x736f6d6570736575
	init1 = 0x646f72616e646f6d
	init2 = 0x6c7967656e657261
	init3 = 0x7465646279746573
)

// Key is a SipHash key: 128 bits, as the two little-endian halves the algorithm mixes into its
// state.
type Key struct {
	k0, k1 uint64
}

// DeriveKey compresses a secret of any length into the 128 bits SipHash takes.
//
// The project's secrets are configuration strings, not 16-byte keys, so they cannot be fed in
// raw: a shorter one would need padding and a longer one would silently ignore everything past
// its sixteenth byte. Hashing first means every byte of the secret reaches the key.
// fareward's src/siphash.rs mirrors this exactly — a difference here rejects every frame.
func DeriveKey(secret []byte) Key {
	digest := sha256.Sum256(secret)
	return Key{
		k0: binary.LittleEndian.Uint64(digest[0:8]),
		k1: binary.LittleEndian.Uint64(digest[8:16]),
	}
}

// Hasher is an incremental SipHash-2-4.
//
// Incremental because every call site tags several separate pieces — a domain string, a nonce, a
// sequence, a payload — and a one-shot interface would force them to concatenate first, which for
// a request-log frame means copying up to 64 KiB per frame just to hash it.
type Hasher struct {
	v0, v1, v2, v3 uint64
	// tail holds the bytes of the current 8-byte word that have not been compressed yet.
	tail     [8]byte
	tailLen  int
	totalLen int
}

func New(key Key) *Hasher {
	return &Hasher{
		v0: key.k0 ^ init0,
		v1: key.k1 ^ init1,
		v2: key.k0 ^ init2,
		v3: key.k1 ^ init3,
	}
}

// Write never fails; the error is there so a Hasher satisfies io.Writer.
func (hasher *Hasher) Write(message []byte) (int, error) {
	written := len(message)
	hasher.totalLen += written

	// Finish the partial word left by the previous Write before consuming whole words.
	if hasher.tailLen > 0 {
		taken := min(len(message), 8-hasher.tailLen)
		copy(hasher.tail[hasher.tailLen:], message[:taken])
		hasher.tailLen += taken
		message = message[taken:]
		if hasher.tailLen < 8 {
			return written, nil
		}
		hasher.compress(binary.LittleEndian.Uint64(hasher.tail[:]))
		hasher.tailLen = 0
	}

	for len(message) >= 8 {
		hasher.compress(binary.LittleEndian.Uint64(message[:8]))
		message = message[8:]
	}

	hasher.tailLen = copy(hasher.tail[:], message)
	return written, nil
}

// WriteString spares the call sites a conversion. The one here does not reach the heap: Write
// does not retain the slice, so escape analysis keeps it on the stack (0 allocs/op measured).
func (hasher *Hasher) WriteString(message string) {
	hasher.Write([]byte(message))
}

func (hasher *Hasher) Sum64() uint64 {
	// The last word is the leftover bytes with the message length's low byte on top, which is
	// what keeps two messages differing only in trailing zeros apart.
	lastWord := uint64(hasher.totalLen&0xff) << 56
	for index, tailByte := range hasher.tail[:hasher.tailLen] {
		lastWord |= uint64(tailByte) << (8 * index)
	}
	hasher.compress(lastWord)

	hasher.v2 ^= 0xff
	for range 4 {
		hasher.round()
	}
	return hasher.v0 ^ hasher.v1 ^ hasher.v2 ^ hasher.v3
}

// compress mixes one message word: two rounds between the two XORs. The "2" of SipHash-2-4.
func (hasher *Hasher) compress(word uint64) {
	hasher.v3 ^= word
	hasher.round()
	hasher.round()
	hasher.v0 ^= word
}

func (hasher *Hasher) round() {
	hasher.v0 += hasher.v1
	hasher.v1 = bits.RotateLeft64(hasher.v1, 13)
	hasher.v1 ^= hasher.v0
	hasher.v0 = bits.RotateLeft64(hasher.v0, 32)

	hasher.v2 += hasher.v3
	hasher.v3 = bits.RotateLeft64(hasher.v3, 16)
	hasher.v3 ^= hasher.v2

	hasher.v0 += hasher.v3
	hasher.v3 = bits.RotateLeft64(hasher.v3, 21)
	hasher.v3 ^= hasher.v0

	hasher.v2 += hasher.v1
	hasher.v1 = bits.RotateLeft64(hasher.v1, 17)
	hasher.v1 ^= hasher.v2
	hasher.v2 = bits.RotateLeft64(hasher.v2, 32)
}
