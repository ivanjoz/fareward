package siphash

import (
	"bytes"
	"testing"
)

// referenceVectors are the 64 vectors from the SipHash paper: key 00 01 … 0f, message 00 01 … n-1.
// fareward's src/siphash.rs asserts the same list, so the two implementations are pinned to the
// specification rather than to each other.
var referenceVectors = [64]uint64{
	0x726fdb47dd0e0e31,
	0x74f839c593dc67fd,
	0x0d6c8009d9a94f5a,
	0x85676696d7fb7e2d,
	0xcf2794e0277187b7,
	0x18765564cd99a68d,
	0xcbc9466e58fee3ce,
	0xab0200f58b01d137,
	0x93f5f5799a932462,
	0x9e0082df0ba9e4b0,
	0x7a5dbbc594ddb9f3,
	0xf4b32f46226bada7,
	0x751e8fbc860ee5fb,
	0x14ea5627c0843d90,
	0xf723ca908e7af2ee,
	0xa129ca6149be45e5,
	0x3f2acc7f57c29bdb,
	0x699ae9f52cbe4794,
	0x4bc1b3f0968dd39c,
	0xbb6dc91da77961bd,
	0xbed65cf21aa2ee98,
	0xd0f2cbb02e3b67c7,
	0x93536795e3a33e88,
	0xa80c038ccd5ccec8,
	0xb8ad50c6f649af94,
	0xbce192de8a85b8ea,
	0x17d835b85bbb15f3,
	0x2f2e6163076bcfad,
	0xde4daaaca71dc9a5,
	0xa6a2506687956571,
	0xad87a3535c49ef28,
	0x32d892fad841c342,
	0x7127512f72f27cce,
	0xa7f32346f95978e3,
	0x12e0b01abb051238,
	0x15e034d40fa197ae,
	0x314dffbe0815a3b4,
	0x027990f029623981,
	0xcadcd4e59ef40c4d,
	0x9abfd8766a33735c,
	0x0e3ea96b5304a7d0,
	0xad0c42d6fc585992,
	0x187306c89bc215a9,
	0xd4a60abcf3792b95,
	0xf935451de4f21df2,
	0xa9538f0419755787,
	0xdb9acddff56ca510,
	0xd06c98cd5c0975eb,
	0xe612a3cb9ecba951,
	0xc766e62cfcadaf96,
	0xee64435a9752fe72,
	0xa192d576b245165a,
	0x0a8787bf8ecb74b2,
	0x81b3e73d20b49b6f,
	0x7fa8220ba3b2ecea,
	0x245731c13ca42499,
	0xb78dbfaf3a8d83bd,
	0xea1ad565322a1a0b,
	0x60e61c23a3795013,
	0x6606d7e446282b93,
	0x6ca4ecb15c5f91e1,
	0x9f626da15c9625f3,
	0xe51b38608ef25f57,
	0x958a324ceb064572,
}

// referenceKey is the paper's key, which is used raw rather than through DeriveKey: the vectors
// pin the primitive, and the derivation is pinned separately by the cross-language tags.
var referenceKey = Key{
	k0: 0x0706050403020100,
	k1: 0x0f0e0d0c0b0a0908,
}

func siphashOf(key Key, message []byte) uint64 {
	hasher := New(key)
	hasher.Write(message)
	return hasher.Sum64()
}

func TestMatchesTheReferenceVectors(t *testing.T) {
	for length, expected := range referenceVectors {
		message := make([]byte, length)
		for index := range message {
			message[index] = byte(index)
		}
		if got := siphashOf(referenceKey, message); got != expected {
			t.Errorf("length %d: got %#016x; want %#016x", length, got, expected)
		}
	}
}

func TestWritingInPiecesMatchesWritingAtOnce(t *testing.T) {
	// Every call site feeds several chunks; splitting must not change the tag.
	key := DeriveKey([]byte("test secret"))
	message := make([]byte, 200)
	for index := range message {
		message[index] = byte(index)
	}
	whole := siphashOf(key, message)

	for _, split := range []int{0, 1, 7, 8, 9, 63, 64, 199, 200} {
		hasher := New(key)
		hasher.Write(message[:split])
		hasher.Write(message[split:])
		if got := hasher.Sum64(); got != whole {
			t.Errorf("split at %d: got %#016x; want %#016x", split, got, whole)
		}
	}
}

func TestEveryByteOfTheSecretReachesTheKey(t *testing.T) {
	// Raw 16-byte truncation would make these two secrets identical.
	first := DeriveKey([]byte("0123456789abcdef-first"))
	second := DeriveKey([]byte("0123456789abcdef-second"))
	if siphashOf(first, []byte("message")) == siphashOf(second, []byte("message")) {
		t.Fatal("secrets differing only past the sixteenth byte produced the same tag")
	}
}

func TestWriteStringMatchesWriteBytes(t *testing.T) {
	key := DeriveKey([]byte("test secret"))
	hasher := New(key)
	hasher.WriteString("sse-bridge:v2|1700000000")
	if hasher.Sum64() != siphashOf(key, []byte("sse-bridge:v2|1700000000")) {
		t.Fatal("WriteString and Write disagree")
	}
}

func TestHasherIsAnIOWriter(t *testing.T) {
	key := DeriveKey([]byte("test secret"))
	hasher := New(key)
	if _, err := bytes.NewReader([]byte("streamed through io.Copy")).WriteTo(hasher); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if hasher.Sum64() != siphashOf(key, []byte("streamed through io.Copy")) {
		t.Fatal("io.Writer path disagrees with Write")
	}
}
