package fareward

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// These twenty bytes are the contract with the Rust decoder, which reads them by offset. The
// vectors here and the ones in parses_the_exact_wire_offsets and
// required_access_slots_are_read_by_offset (limiter/protocol.rs) are the same charge written from
// both ends. This test and its Rust twin are the only thing holding the layout.
func TestChargePayloadMatchesTheWireOffsets(t *testing.T) {
	payload, err := encodeCharge(0x123456, 42, 103, 300, 25, []uint16{0x0139, 0x008B}, false)
	if err != nil {
		t.Fatalf("encodeCharge refused a valid charge: %v", err)
	}

	want := []byte{
		0x12, 0x34, 0x56, // company
		0x00, 0x00, 0x2A, // user
		0x00, 0x67, // route 103
		0x01, 0x2C, // cpu 300
		0x00, 0x19, // inference 25
		0x01, 0x39, // required access slot 0
		0x00, 0x8B, // required access slot 1
		0x00, 0x00, // slot 2 unused
		0x00, 0x00, // slot 3 unused
	}
	if !bytes.Equal(payload, want) {
		t.Fatalf("charge payload = % X; want % X", payload, want)
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

// The reply's detail field. Zero when a check was requested means the daemon never answered it,
// which must fail closed: failing open would silently unauthorize every gated route the moment the
// two binaries drifted apart.
func TestAccessVerdictDecoding(t *testing.T) {
	if _, err := decodeAccessResponse(0, nil, false); err != nil {
		t.Fatalf("an unrequested check reported %v", err)
	}
	// Granted, slot 0, no sub-accesses.
	grant, err := decodeAccessResponse(1|(0b1<<3), nil, true)
	if err != nil || grant == nil || grant.GrantedSlots != 0b1 {
		t.Fatalf("a granted check decoded to %+v, %v", grant, err)
	}

	for _, check := range []struct {
		detail         uint16
		identityFailed bool
	}{{2, false}, {3, true}, {4, true}} {
		_, err := decodeAccessResponse(check.detail, nil, true)
		denied, ok := err.(*AccessDenied)
		if !ok {
			t.Fatalf("detail %d decoded as %T: %v", check.detail, err, err)
		}
		if denied.IdentityFailed() != check.identityFailed {
			t.Fatalf("detail %d: IdentityFailed() = %v; want %v",
				check.detail, denied.IdentityFailed(), check.identityFailed)
		}
		if !IsAccessDeniedError(err) {
			t.Fatalf("detail %d was not recognised as an access denial", check.detail)
		}
	}

	// A daemon that ignored the slots, and one that answered something invented.
	for _, detail := range []uint16{0, 5, 7} {
		if _, err := decodeAccessResponse(detail, nil, true); !errors.Is(err, ErrFarewardUnavailable) {
			t.Fatalf("detail %d decoded as %v; want unavailability", detail, err)
		}
	}
}

// The masks and the tail describe each other, so every way they can disagree is a desynchronized
// pair of binaries — refused, because half-reading the tail attributes one access's sub-accesses to
// another.
func TestAccessGrantSplitsTheReplyTailPerSlot(t *testing.T) {
	// Slots 0 and 2 granted; only slot 2 carries sub bytes, and its run is two bytes long.
	detail := uint16(1) | (0b101 << 3) | (0b100 << 7)
	grant, err := decodeAccessResponse(detail, []byte{0x81, 0x20}, true)
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

	// Two slots, two runs, split at the MORE bit rather than in the middle.
	detail = uint16(1) | (0b11 << 3) | (0b11 << 7)
	grant, err = decodeAccessResponse(detail, []byte{0x06, 0x81, 0x20}, true)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if !bytes.Equal(grant.SubAccesoBytes[0], []byte{0x06}) ||
		!bytes.Equal(grant.SubAccesoBytes[1], []byte{0x81, 0x20}) {
		t.Fatalf("runs split wrongly: %v", grant.SubAccesoBytes)
	}

	for name, check := range map[string]struct {
		detail uint16
		extra  []byte
	}{
		"sub-accesses on an ungranted slot": {uint16(1) | (0b1 << 3) | (0b10 << 7), []byte{0x01}},
		"tail ends mid run":                 {uint16(1) | (0b1 << 3) | (0b1 << 7), []byte{0x81}},
		"tail longer than the mask claims":  {uint16(1) | (0b1 << 3) | (0b1 << 7), []byte{0x01, 0x02}},
		"tail present with no marked slot":  {uint16(1) | (0b1 << 3), []byte{0x01}},
	} {
		if _, err := decodeAccessResponse(check.detail, check.extra, true); err == nil {
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

// The extra-credit mark rides in the high bit of the route field, which maxChargeRouteID leaves
// free. Two things must hold and neither is visible from the Rust side alone: the bit lands on
// byte 6 and nowhere else, and a route number can never set it by itself.
func TestTheExtraCreditFlagRidesInTheRouteField(t *testing.T) {
	unmarked, err := encodeCharge(1, 1, 103, 2, 0, nil, false)
	if err != nil {
		t.Fatalf("encodeCharge refused a valid charge: %v", err)
	}
	marked, err := encodeCharge(1, 1, 103, 2, 0, nil, true)
	if err != nil {
		t.Fatalf("encodeCharge refused a marked charge: %v", err)
	}
	if marked[6] != unmarked[6]|0x80 {
		t.Fatalf("the mark did not set the high bit of byte 6: % X vs % X", marked, unmarked)
	}
	// Byte 6 is the only difference: a mark must not move a single credit or access slot.
	marked[6] = unmarked[6]
	if !bytes.Equal(marked, unmarked) {
		t.Fatalf("marking a charge changed more than the route field: % X vs % X", marked, unmarked)
	}

	// The highest encodable route still leaves the bit free, which is what makes the field safe to
	// share: fourteen bits of route against a bit-15 marker.
	for _, routeID := range []int16{0, 1, 103, maxChargeRouteID} {
		payload, err := encodeCharge(1, 1, routeID, 2, 0, nil, false)
		if err != nil {
			t.Fatalf("route %d was refused: %v", routeID, err)
		}
		if payload[6]&0x80 != 0 {
			t.Fatalf("route %d set the extra-credit flag by itself", routeID)
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
		0x01, 0x12, 0x34, 0x56, 0x00, 0x00, 0x2A, 0x00, 0x67, 0x01, 0x2C, 0x00, 0x19, 0x01,
		0x39, 0x00, 0x8B, 0x00, 0x00, 0x00, 0x00,
		0xD2, 0xA6, 0x9B, 0x95, 0xEC, 0x5E, 0x0C, 0x94,
	}
	if !bytes.Equal(frame, want) {
		t.Fatalf("charge frame = % X; want % X", frame, want)
	}
	// The tag is bound to the sequence, so frame two of a connection differs in its last eight bytes.
	next := buildFarewardFrame(secret, &nonce, 1, opcodeChargeCredits, payload)
	wantTag := []byte{0xF1, 0x7B, 0x93, 0xF3, 0xA4, 0x9D, 0x7D, 0x3E}
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
		0x06, 0x00, 0x00, 0x07, 0x00, 0x01, 0x2C,
		0xB7, 0x90, 0xDA, 0x17, 0xF1, 0x4C, 0xCD, 0x92,
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

// The operator's own company runs without a budget. With no daemon configured, an exempt
// charge has to come back nil where any other company gets ErrCreditLimiterMissing — that
// difference is the whole exemption, and it is what keeps company 1 usable when the limiter
// says the tenant is out of credit.
func TestTheOperatorCompanyIsExemptFromCreditBudgets(t *testing.T) {
	if _, err := chargeConfiguredCredits(
		context.Background(), CreditExemptCompanyID, 1, 10, 5, 0, nil, false,
	); err != nil {
		t.Fatalf("the exempt company must not be charged, got %v", err)
	}

	// Any other tenant still reaches the limiter, so the exemption is not a global bypass.
	if _, err := chargeConfiguredCredits(
		context.Background(), CreditExemptCompanyID+1, 1, 10, 5, 0, nil, false,
	); err == nil {
		t.Fatal("a non-exempt company must still be metered")
	}

	// Inference credits go through the same seam, so the agent is exempt too.
	if _, err := chargeConfiguredCredits(
		context.Background(), CreditExemptCompanyID, 1, 10, 0, 500, nil, false,
	); err != nil {
		t.Fatalf("inference credits must be exempt as well, got %v", err)
	}
}

// Exemption is from the budget, not from permissions: a frame that still has an access to
// check must reach the daemon rather than be short-circuited to nil.
func TestTheExemptCompanyIsStillAuthorized(t *testing.T) {
	_, err := chargeConfiguredCredits(
		context.Background(), CreditExemptCompanyID, 1, 10, 5, 0, []uint16{9}, false)
	if err == nil {
		t.Fatal("an access check must still be sent for the exempt company")
	}
	if !errors.Is(err, ErrCreditLimiterMissing) {
		t.Fatalf("expected the frame to reach the limiter, got %v", err)
	}
}
