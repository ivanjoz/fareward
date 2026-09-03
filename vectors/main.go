// Command vectors prints the session-token vectors the bridge's Rust tests are
// pinned against.
//
// The tokens the browser presents are produced by the backend, so the only
// honest source for a test vector is the Go code that produces them: colbin at
// the version backend/go.mod pins, and the same keyed hash core computes. This
// program is a standalone module so it can depend on colbin without joining the
// backend's module graph, and it prints rather than writes, because the vectors
// are a handful of constants that belong next to the assertions that use them.
//
//	go run ./vectors
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/ivanjoz/colbin"
	"github.com/ivanjoz/fareward/go/siphash"
	"golang.org/x/crypto/blake2s"
)

// UsuarioToken mirrors backend/core.UsuarioToken minus its json tags, which
// rename fields in colbin's schema section without touching the binary payload,
// and minus its Error field, which carries cb:"-" and is never encoded.
type UsuarioToken struct {
	CompanyID int32
	ID        int32
	Created   int32
	Hash      []byte
	User      string
}

// testSecret is the secret the Rust tests declare. It is a test fixture, not a
// deployed key.
const testSecret = "K1OzWIN0yarCc9ge"

// computeHash is core.ComputeUsuarioTokenHash: the token's own keyed BLAKE2s-128
// tag, which the bridge recomputes to prove the identity was issued by the backend.
func computeHash(token UsuarioToken) []byte {
	payload := make([]byte, 12)
	binary.BigEndian.PutUint32(payload[0:4], uint32(token.CompanyID))
	binary.BigEndian.PutUint32(payload[4:8], uint32(token.ID))
	binary.BigEndian.PutUint32(payload[8:12], uint32(token.Created))

	tokenKey := sha256.Sum256([]byte(testSecret))
	hasher, err := blake2s.New128(tokenKey[:])
	if err != nil {
		panic(err)
	}
	hasher.Write([]byte("usrToken:v3"))
	hasher.Write(payload)
	hasher.Write([]byte(token.User))
	return hasher.Sum(nil)
}

// makeServiceAuthHeader is backend/agent.makeBridgeServiceAuthHeader at a fixed
// timestamp: the other value the bridge's Rust tests are pinned against.
func makeServiceAuthHeader(unixSeconds int64) string {
	hasher := siphash.New(siphash.DeriveKey([]byte(testSecret)))
	hasher.WriteString(fmt.Sprintf("sse-bridge:v2|%d", unixSeconds))
	return fmt.Sprintf("%d.%016x", unixSeconds, hasher.Sum64())
}

// makeB64UrlEncode is core.MakeB64UrlEncode, the alphabet the backend publishes
// the token under.
func makeB64UrlEncode(s string) string {
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "+", "-")
	return strings.ReplaceAll(s, "=", "~")
}

func main() {
	cases := []struct {
		name  string
		token UsuarioToken
	}{
		{"plain", UsuarioToken{CompanyID: 7, ID: 42, Created: 1234, User: "tester"}},
		{"empty-user", UsuarioToken{CompanyID: 1, ID: 1, User: ""}},
		{"int32-max", UsuarioToken{CompanyID: 2147483647, ID: 2147483647, Created: 2147483647, User: "x"}},
		{"accented", UsuarioToken{CompanyID: 999999, ID: 12345, Created: 1700000000, User: "ñandú@example.com"}},
		{"long-user", UsuarioToken{CompanyID: 128, ID: 127, Created: 65536, User: "a-very-long-user-name-for-width-testing"}},
		// A negative id never reaches the wire from a real login, but it is what
		// clears ALL_POSITIVE, so the zigzag path has a vector too.
		{"negative-created", UsuarioToken{CompanyID: 3, ID: 4, Created: -5, User: "neg"}},
	}

	fmt.Printf("colbin %s, secret %q\n\n", colbinVersion(), testSecret)
	for _, c := range cases {
		c.token.Hash = computeHash(c.token)
		data, err := colbin.Marshal(c.token)
		if err != nil {
			panic(err)
		}
		standard := base64.StdEncoding.EncodeToString(data)
		fmt.Printf("%-16s %2d B  hash=%x\n", c.name, len(data), c.token.Hash)
		fmt.Printf("  base64      %s\n", standard)
		fmt.Printf("  url-alphabet %s\n\n", makeB64UrlEncode(standard))
	}

	// A token whose Hash is empty: colbin omits a zero-valued field entirely, so this payload
	// carries no hash at all. The bridge must refuse it rather than read sixteen zeros and
	// compare them, which is the one way a widened tag could be quietly bypassed.
	hashless, err := colbin.Marshal(UsuarioToken{CompanyID: 7, ID: 42, Created: 1234, User: "tester"})
	if err != nil {
		panic(err)
	}
	fmt.Printf("hashless token: %s\n", makeB64UrlEncode(base64.StdEncoding.EncodeToString(hashless)))

	fmt.Printf("X-Bridge-Auth at 1700000000: %s\n", makeServiceAuthHeader(1_700_000_000))
}

// colbinVersion is a label for the printout, so a regenerated vector says which
// format wrote it.
func colbinVersion() string {
	if colbin.OmitEmpty() {
		return "omit-empty on"
	}
	return "omit-empty off (the backend's setting for this type)"
}
