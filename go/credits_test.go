package fareward

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

// The payload is a colbin message, so the contract with the Rust decoder is the field ids, not
// byte offsets. Decoding it back is what asserts them: a field encoded under the wrong id decodes
// as absent on the far side, which reaches the daemon as a zero and charges the wrong route.
func TestChargeRoundTripsEveryField(t *testing.T) {
	payload, err := encodeCharge(0x123456, 42, 103, 300, 25, []uint16{0x0139, 0x008B}, false)
	if err != nil {
		t.Fatalf("encodeCharge refused a valid charge: %v", err)
	}

	var decoded chargeFrame
	if err := chargeCodec.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	want := chargeFrame{
		CompanyID: 0x123456,
		UserID:    42,
		RouteID:   103,
		CPU:       300,
		Inference: 25,
		Access1:   0x0139,
		Access2:   0x008B,
	}
	if decoded != want {
		t.Fatalf("charge payload decoded as %+v; want %+v", decoded, want)
	}
}

// The common case the codec was adopted for: an ungated request carries no access field at all,
// where the fixed layout always spent eight bytes on four empty slots.
func TestAnUngatedChargeCarriesNoAccessSlots(t *testing.T) {
	ungated, err := encodeCharge(7, 1, 103, 300, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	gated, err := encodeCharge(7, 1, 103, 300, 0, []uint16{0x0139}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ungated) >= len(gated) {
		t.Fatalf("an ungated charge is %d bytes against %d for a gated one", len(ungated), len(gated))
	}
	if len(ungated) > 12 {
		t.Fatalf("an ungated charge is %d bytes", len(ungated))
	}
}

// Zero terminates the slot list on the far side, so it can never also be a grant, and a route
// mapped to more accesses than fit is a configuration bug caught here rather than a rejected frame.
func TestRequiredAccessSlotsAreValidated(t *testing.T) {
	tooMany := make([]uint16, MaxRequiredAccess+1)
	for slot := range tooMany {
		tooMany[slot] = uint16(slot+1) << 2
	}
	if _, err := encodeCharge(1, 1, 1, 1, 0, tooMany, false); err == nil {
		t.Fatal("a route requiring more accesses than the frame holds was accepted")
	}
	if _, err := encodeCharge(1, 1, 1, 1, 0, []uint16{0x008B, 0}, false); err == nil {
		t.Fatal("a zero required access was accepted")
	}
	full := make([]uint16, MaxRequiredAccess)
	for slot := range full {
		full[slot] = uint16(slot+1) << 2
	}
	if _, err := encodeCharge(1, 1, 1, 1, 0, full, false); err != nil {
		t.Fatalf("a full slot list was refused: %v", err)
	}
}

// An authorize-only frame carries no credits. It exists because creditControlRoutes skips the
// charge, and three of those routes are access-mapped: skipping the frame with them would leave
// them open to any session.
func TestAFrameNeedsCreditsOrARequiredAccess(t *testing.T) {
	if _, err := encodeCharge(1, 1, 1, 0, 0, nil, false); err == nil {
		t.Fatal("a frame with neither credits nor a required access was accepted")
	}
	if _, err := encodeCharge(1, 1, 1, 0, 0, []uint16{0x008B}, false); err != nil {
		t.Fatalf("an authorize-only frame was refused: %v", err)
	}
}

// A denial's body is the reason and nothing else, now that "not requested" and "granted" are shapes
// of their own rather than codes sharing a field with it.
func TestAccessDenialDecoding(t *testing.T) {
	for _, check := range []struct {
		reason         byte
		identityFailed bool
	}{{2, false}, {3, true}, {4, true}} {
		err := decodeAccessDenied([]byte{check.reason})
		denied, ok := err.(*AccessDenied)
		if !ok {
			t.Fatalf("reason %d decoded as %T: %v", check.reason, err, err)
		}
		if denied.IdentityFailed() != check.identityFailed {
			t.Fatalf("reason %d: IdentityFailed() = %v; want %v",
				check.reason, denied.IdentityFailed(), check.identityFailed)
		}
		if !IsAccessDeniedError(err) {
			t.Fatalf("reason %d was not recognised as an access denial", check.reason)
		}
	}

	// A reason this client does not know, and a denial carrying nothing at all: both are a layout
	// disagreement rather than a verdict, so neither may read as a permission.
	for name, body := range map[string][]byte{"invented reason": {7}, "empty body": {}} {
		err := decodeAccessDenied(body)
		if !errors.Is(err, ErrFarewardUnavailable) {
			t.Fatalf("%s decoded as %v; want unavailability", name, err)
		}
		if IsAccessDeniedError(err) {
			t.Fatalf("%s read as a real denial", name)
		}
	}
}

// The masks and the sub bytes describe each other, so every way they can disagree is a
// desynchronized pair of binaries — refused, because half-reading them attributes one access's
// sub-accesses to another.
func TestAccessGrantSplitsTheBodyPerSlot(t *testing.T) {
	// Slots 0 and 2 granted; only slot 2 carries sub bytes, and its run is two bytes long.
	grant, err := decodeAccessGrant([]byte{0b101, 0b100, 2, 0x81, 0x20})
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if grant.GrantedSlots != 0b101 {
		t.Fatalf("GrantedSlots = %b; want 101", grant.GrantedSlots)
	}
	if len(grant.SubAccesoBytes) != 1 ||
		!bytes.Equal(grant.SubAccesoBytes[2], []byte{0x81, 0x20}) {
		t.Fatalf("SubAccesoBytes = %v", grant.SubAccesoBytes)
	}

	// A grant with no sub-accesses at all is the common case and carries only its masks.
	grant, err = decodeAccessGrant([]byte{0b1, 0, 0})
	if err != nil || grant.GrantedSlots != 0b1 || len(grant.SubAccesoBytes) != 0 {
		t.Fatalf("a bare grant decoded to %+v, %v", grant, err)
	}

	// Two slots, two runs, split at the MORE bit rather than in the middle.
	grant, err = decodeAccessGrant([]byte{0b11, 0b11, 3, 0x06, 0x81, 0x20})
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if !bytes.Equal(grant.SubAccesoBytes[0], []byte{0x06}) ||
		!bytes.Equal(grant.SubAccesoBytes[1], []byte{0x81, 0x20}) {
		t.Fatalf("runs split wrongly: %v", grant.SubAccesoBytes)
	}

	for name, body := range map[string][]byte{
		"sub-accesses on an ungranted slot":      {0b1, 0b10, 1, 0x01},
		"body ends mid run":                      {0b1, 0b1, 1, 0x81},
		"more sub bytes than the mask claims":    {0b1, 0b1, 2, 0x01, 0x02},
		"sub bytes with no marked slot":          {0b1, 0, 1, 0x01},
		"declared count disagrees with the body": {0b1, 0b1, 5, 0x01},
		// A daemon that ignored the slots would grant nothing and still call it a grant.
		"granted nothing": {0, 0, 0},
		"truncated":       {0b1, 0b1},
	} {
		if _, err := decodeAccessGrant(body); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// The GET split: the base is what the pre-handler frame charges, the top-up is the difference.
func TestGetBaseAndTopUpSumToTheWholeCharge(t *testing.T) {
	base, err := APICPUBaseCredits("GET")
	if err != nil || base != 2 {
		t.Fatalf("APICPUBaseCredits(GET) = %d, %v; want 2", base, err)
	}
	// A response inside the first block owes exactly the base, so no second frame is sent at all.
	for _, responseBytes := range []int{0, 4 * 1024, 8 * 1024} {
		total, _ := APICPUCredits("GET", responseBytes)
		if total != base {
			t.Fatalf("a %d-byte GET response owes %d; want just the base %d",
				responseBytes, total, base)
		}
	}
	// Past it, base plus top-up must equal what the single old charge would have been.
	for _, responseBytes := range []int{8*1024 + 1, 24 * 1024, 24*1024 + 1, 1 << 20} {
		total, _ := APICPUCredits("GET", responseBytes)
		if total <= base {
			t.Fatalf("a %d-byte GET response owes only %d", responseBytes, total)
		}
		if base+(total-base) != total {
			t.Fatalf("the split does not reconstruct the charge for %d bytes", responseBytes)
		}
	}
}

// Route zero is a request that matched no generated route. Its credits are real, so refusing it
// would make an unnumbered handler free; the ceiling it is checked against is the blob's, not the
// route table's, because this side must not go stale when a handler is added.
func TestChargeAcceptsUnknownRoutesAndRefusesUnencodableOnes(t *testing.T) {
	for _, routeID := range []int16{0, 1, maxChargeRouteID} {
		if _, err := encodeCharge(1, 1, routeID, 1, 0, nil, false); err != nil {
			t.Fatalf("route %d was refused: %v", routeID, err)
		}
	}
	if _, err := encodeCharge(1, 1, maxChargeRouteID+1, 1, 0, nil, false); err == nil {
		t.Fatal("a route past the encoding ceiling was accepted")
	}
}

// The extra-credit mark used to ride in the high bit of the route field, which made "is this route
// number clean" a real question on both sides. It is a field of its own now, so the two cannot
// interfere — and a false one is not written at all, which is what makes it free on every frame
// that is not a read.
func TestTheExtraCreditFlagIsAFieldOfItsOwn(t *testing.T) {
	unmarked, err := encodeCharge(1, 1, 103, 2, 0, nil, false)
	if err != nil {
		t.Fatalf("encodeCharge refused a valid charge: %v", err)
	}
	marked, err := encodeCharge(1, 1, 103, 2, 0, nil, true)
	if err != nil {
		t.Fatalf("encodeCharge refused a marked charge: %v", err)
	}
	if len(marked) != len(unmarked)+1 {
		t.Fatalf("the mark cost %d bytes, want one", len(marked)-len(unmarked))
	}

	// Marking must not move a single credit or access slot.
	var markedFrame, unmarkedFrame chargeFrame
	if err := chargeCodec.Unmarshal(marked, &markedFrame); err != nil {
		t.Fatal(err)
	}
	if err := chargeCodec.Unmarshal(unmarked, &unmarkedFrame); err != nil {
		t.Fatal(err)
	}
	if !markedFrame.ExtraAllowed {
		t.Fatal("a marked charge decoded without its flag")
	}
	markedFrame.ExtraAllowed = false
	if markedFrame != unmarkedFrame {
		t.Fatalf("marking changed more than the flag: %+v vs %+v", markedFrame, unmarkedFrame)
	}

	// And no route number sets it by itself, at any width.
	for _, routeID := range []int16{0, 1, 103, maxChargeRouteID} {
		payload, err := encodeCharge(1, 1, routeID, 2, 0, nil, false)
		if err != nil {
			t.Fatalf("route %d was refused: %v", routeID, err)
		}
		var frame chargeFrame
		if err := chargeCodec.Unmarshal(payload, &frame); err != nil {
			t.Fatal(err)
		}
		if frame.ExtraAllowed || frame.RouteID != uint16(routeID) {
			t.Fatalf("route %d decoded as %+v", routeID, frame)
		}
	}
}

func TestCreditFormulasRoundPartialBlocksUp(t *testing.T) {
	checks := []struct {
		method string
		bytes  int
		want   uint16
	}{
		{"GET", 0, 2}, {"GET", 8 * 1024, 2}, {"GET", 8*1024 + 1, 3},
		{"GET", 24 * 1024, 3}, {"GET", 24*1024 + 1, 4},
		{"POST", 0, 5}, {"POST", 8 * 1024, 5}, {"POST", 8*1024 + 1, 6},
		{"POST", 16 * 1024, 6}, {"POST", 16*1024 + 1, 7},
		// PUT is a write like POST and shares its tariff exactly; see APICPUCredits.
		{"PUT", 0, 5}, {"PUT", 8 * 1024, 5}, {"PUT", 8*1024 + 1, 6},
		{"PUT", 16 * 1024, 6}, {"PUT", 16*1024 + 1, 7},
		// Lower case reaches the same case arm, since the switch upper-cases first.
		{"put", 16*1024 + 1, 7}, {"post", 16*1024 + 1, 7},
	}
	for _, check := range checks {
		got, err := APICPUCredits(check.method, check.bytes)
		if err != nil || got != check.want {
			t.Fatalf("APICPUCredits(%q, %d) = %d, %v; want %d", check.method, check.bytes, got, err, check.want)
		}
	}
	// A method with no tariff must error rather than silently cost nothing — that error is what
	// makes chargedMethodFor's guard necessary instead of decorative.
	if _, err := APICPUCredits("DELETE", 0); err == nil {
		t.Fatal("an unknown method was given a tariff")
	}

	inference, err := InferenceCredits(8*1024+1, 8*1024+1)
	if err != nil || inference != 6 {
		t.Fatalf("InferenceCredits() = %d, %v; want 6", inference, err)
	}
}

func TestMonthlyCreditLimitResponseUsesTheReservedWindow(t *testing.T) {
	err := decodeCreditLimitResponse(0b1_1110)
	limit, ok := err.(*CreditLimitExceeded)
	if !ok {
		t.Fatalf("monthly response decoded as %T: %v", err, err)
	}
	if !limit.Company || limit.Window != "month" || !limit.CPU || !limit.Inference {
		t.Fatalf("monthly response decoded incorrectly: %+v", limit)
	}
}

// The whole signed charge frame, pinned against matches_the_go_client_vectors in
// fareward/src/service/auth.rs. The payload test above proves the fields sit at the right
// offsets; this proves the twenty bytes are also what gets signed, which is what a widened payload
// could quietly get wrong — the tag would still verify on both ends while covering different bytes.
func TestChargeFrameMatchesTheRustAuthVector(t *testing.T) {
	secret := []byte("test-secret")
	nonce := [farewardNonceSize]byte{1, 2, 3, 4, 5, 6, 7, 8}
	payload, err := encodeCharge(0x123456, 42, 103, 300, 25, []uint16{0x0139, 0x008B}, false)
	if err != nil {
		t.Fatalf("encodeCharge refused a valid charge: %v", err)
	}

	frame := buildFarewardFrame(secret, &nonce, 0, opcodeChargeCredits, payload)
	want := []byte{
		0x01, 0x00, 0x13,
		0xD0, 0x0B, 0x56, 0x34, 0x12, 0x19, 0x2A, 0x28, 0x67, 0x39, 0x2C, 0x01, 0x48, 0x19,
		0x69, 0x39, 0x01, 0x78, 0x8B,
		0x4F, 0xC0, 0xB8, 0xD1, 0xBA, 0xE0, 0x72, 0x76,
	}
	if !bytes.Equal(frame, want) {
		t.Fatalf("charge frame = % X; want % X", frame, want)
	}
	// The tag is bound to the sequence, so frame two of a connection differs in its last eight bytes.
	next := buildFarewardFrame(secret, &nonce, 1, opcodeChargeCredits, payload)
	wantTag := []byte{0xD3, 0x87, 0x19, 0xB6, 0xF0, 0x84, 0x90, 0x66}
	if !bytes.Equal(next[len(next)-farewardAuthTagSize:], wantTag) {
		t.Fatalf("sequence 1 tag = % X; want % X", next[len(next)-farewardAuthTagSize:], wantTag)
	}
}

// The invalidation frame, pinned against the same Rust vector set.
func TestAccessInvalidationFrameMatchesTheRustAuthVector(t *testing.T) {
	payload, err := encodeAccessInvalidation(7, 300)
	if err != nil {
		t.Fatalf("encodeAccessInvalidation refused a valid target: %v", err)
	}
	nonce := [farewardNonceSize]byte{1, 2, 3, 4, 5, 6, 7, 8}
	frame := buildFarewardFrame([]byte("test-secret"), &nonce, 0, opcodeInvalidateUserAccess, payload)
	want := []byte{
		0x06, 0x00, 0x06,
		0xD0, 0x09, 0x07, 0x1A, 0x2C, 0x01,
		0x02, 0xA6, 0x4D, 0x42, 0xA1, 0x56, 0xA8, 0x01,
	}
	if !bytes.Equal(frame, want) {
		t.Fatalf("invalidation frame = % X; want % X", frame, want)
	}

	// Zero is the wildcard and must encode; a company of zero has no meaning and must not.
	if _, err := encodeAccessInvalidation(7, InvalidateAllCompanyUsers); err != nil {
		t.Fatalf("the company wildcard was refused: %v", err)
	}
	if _, err := encodeAccessInvalidation(0, 1); err == nil {
		t.Fatal("company zero was accepted")
	}
}

// The regression this replaces: the operator's credits used to be zeroed here before the frame was
// built, so the daemon never saw a charge, never wrote a credit_usage row, and every number on the
// operator's own usage report sat at zero with nothing to explain it. The frame must carry the real
// amounts — what the operator is spared is the refusal, and that lives in the router.
func TestTheOperatorCompanyIsChargedLikeAnyTenant(t *testing.T) {
	stub := startMuxDaemonStub(t)
	stub.answer = func(uint64, byte, []byte) (byte, []byte, bool) { return replyChargeAllowed, nil, true }
	installStubAsConfiguredFareward(t, stub)

	if _, err := chargeConfiguredCredits(
		context.Background(), OperatorCompanyID, 1, 10, 300, 25, nil, false,
	); err != nil {
		t.Fatalf("the operator charge was refused: %v", err)
	}

	// Read with a deadline rather than blocking: the regression's shape was "no frame at all", and
	// a test that hangs on it reports a timeout instead of the assertion that failed.
	var frame []byte
	select {
	case frame = <-stub.frames:
	case <-time.After(2 * time.Second):
		t.Fatal("no charge frame reached the daemon for the operator company")
	}

	var charge chargeFrame
	if err := chargeCodec.Unmarshal(framePayload(t, frame), &charge); err != nil {
		t.Fatal(err)
	}
	if charge.CPU != 300 {
		t.Fatalf("cpu credits on the wire = %d; want the 300 that were asked for", charge.CPU)
	}
	if charge.Inference != 25 {
		t.Fatalf("inference credits on the wire = %d; want the 25 that were asked for", charge.Inference)
	}
}

// installStubAsConfiguredFareward points the process-wide client at the stub and puts it back
// afterwards: the tests around this one assert what happens with no daemon at all.
func installStubAsConfiguredFareward(t *testing.T, stub *muxDaemonStub) {
	t.Helper()
	if err := ConfigureFareward(stub.listener.Addr().String(), "test-secret"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		configuredFarewardMu.Lock()
		configuredFareward = nil
		configuredFarewardMu.Unlock()
	})
}

// With no daemon there is no decision, so the charge fails closed — except for the operator on a
// frame that asks for no authorization, which is the one bypass left: being locked out by the very
// process that needs fixing is the failure it allows for.
func TestAMissingDaemonOnlyLetsTheOperatorThrough(t *testing.T) {
	if _, err := chargeConfiguredCredits(
		context.Background(), OperatorCompanyID, 1, 10, 5, 0, nil, false,
	); err != nil {
		t.Fatalf("the operator must get through a dead daemon, got %v", err)
	}

	// Any other tenant is refused, so the bypass is not a global one.
	if _, err := chargeConfiguredCredits(
		context.Background(), OperatorCompanyID+1, 1, 10, 5, 0, nil, false,
	); !errors.Is(err, ErrCreditLimiterMissing) {
		t.Fatalf("a tenant must still fail closed, got %v", err)
	}

	// An unenforced permission is not a degraded mode: a frame carrying accesses is refused even
	// for the operator, because there is nothing here that could check them.
	if _, err := chargeConfiguredCredits(
		context.Background(), OperatorCompanyID, 1, 10, 5, 0, []uint16{9}, false,
	); !errors.Is(err, ErrCreditLimiterMissing) {
		t.Fatalf("an access check cannot be skipped for the operator, got %v", err)
	}
}
