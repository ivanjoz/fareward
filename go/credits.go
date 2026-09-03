package fareward

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// Opcode 0x01: [opcode][company:u24][user:u24][route:u16][cpu:u16][inference:u16]
	// [requiredAccess:4xu16][tag:8].
	creditChargePayloadSize = 12 + 2*MaxRequiredAccess

	// MaxRequiredAccess is how many packed grants one frame can carry. access_list.yml maps at most
	// two accesses to any one backend route, so this is 2x headroom for eight bytes of frame. A
	// route needing a fifth is refused here rather than by the daemon, for the same reason
	// maxChargeRouteID is: a rejected frame is indistinguishable from the daemon being down and
	// would surface as a 503 instead of as the bug it is. TestEveryRouteFitsTheRequiredAccessSlots
	// is what catches it before a request ever does.
	MaxRequiredAccess = 4

	creditBlockBytes = 8 * 1024

	// Fourteen bits of the persisted blob's two-byte header, mirrored from
	// fareward/src/limiter/credits_blob.rs. Refused here rather than at the daemon so an
	// unencodable route is a caller's error and not a rejected frame — a rejection would be
	// indistinguishable from the limiter being down and would produce the wrong 503 response.
	maxChargeRouteID = 16_383

	// subAccesoMoreBit terminates a sub-access run: set means another byte follows. The runs
	// themselves are opaque here — see AccessGrant.
	subAccesoMoreBit = 0x80

	// extraCreditFlag rides in the high bit of the route field, which maxChargeRouteID leaves free.
	// Set, it tells the daemon this charge is a read and may therefore fall back to the company's
	// extra daily pool once normal quota refuses. Mirrored from EXTRA_CREDIT_FLAG in
	// fareward/src/limiter/protocol.rs.
	//
	// It is a permission and not an instruction: an eligible frame that fits in normal quota is
	// charged normally. Only reads carry it, because the pool exists to keep a tenant out of credit
	// able to look at its data, not to keep writing.
	extraCreditFlag = uint16(0x8000)
)

var ErrCreditLimiterMissing = errors.New("credit rate limiter is not configured")

// accessDeniedReason is the low three bits of the reply frame's detail field. Zero means no
// authorization was requested and one means granted, which is why the refusals start at two —
// mirrored from fareward/src/limiter/access.rs.
type accessDeniedReason uint16

const (
	accessGranted      accessDeniedReason = 1
	accessReasonNone   accessDeniedReason = 2
	accessReasonNoUser accessDeniedReason = 3
	accessReasonStatus accessDeniedReason = 4
)

// How the daemon packs a granted verdict into the reply's sixteen-bit detail field. The code keeps
// the low bits it always had; the two masks occupy space that used to be permanently zero.
//
//	bits  0..2  the code above
//	bits  3..6  granted mask   — bit N = requiredAccess[N] is held
//	bits  7..10 has-subs mask  — bit N = slot N contributed bytes to the reply tail
const (
	accessCodeMask     = 0b111
	accessGrantedShift = 3
	accessHasSubsShift = 7
	accessSlotMask     = 0b1111
)

// AccessGrant is what one authorized route learned about the caller: which of the accesses it
// required they hold, and the sub-accesses riding on each.
//
// The sub-access bytes stay in their wire form here on purpose. This package answers a verdict, not
// a meaning — it holds no copy of the catalogue, so it cannot say what sub-access 3 of access 10
// is, and "id 1 means Todos" is a rule for the side that does.
type AccessGrant struct {
	// GrantedSlots is a bitmask over the requiredAccess slice the caller passed in.
	GrantedSlots uint8
	// SubAccesoBytes maps a requiredAccess slot index to that access's sub-access run, in the
	// `[1 bit MORE][7 bits flags]` encoding of accesos_sub_computed. Absent means no sub-accesses.
	SubAccesoBytes map[int][]byte
}

// AccessDenied is the daemon's authorization refusal. Separate from CreditLimitExceeded because the
// two are different answers: one says the tenant has spent its allowance, the other says this
// session may not do this at all.
type AccessDenied struct {
	reason accessDeniedReason
}

func (denied *AccessDenied) Error() string {
	switch denied.reason {
	case accessReasonNoUser:
		return "no such user in this company"
	case accessReasonStatus:
		return "the user is not active"
	default:
		return "the user does not hold the required access"
	}
}

// IdentityFailed separates "this session is not valid" from "this session may not do this". The
// caller turns the first into a 401 and the second into a 403: a client that has lost its identity
// must re-authenticate, while one that merely lacks a permission must not.
func (denied *AccessDenied) IdentityFailed() bool {
	return denied.reason == accessReasonNoUser || denied.reason == accessReasonStatus
}

// CreditLimitExceeded is the authenticated one-byte rejection returned by the Rust service.
type CreditLimitExceeded struct {
	Code      uint8
	Company   bool
	Window    string
	CPU       bool
	Inference bool
}

func (limit *CreditLimitExceeded) Error() string {
	scope := "user"
	if limit.Company {
		scope = "company"
	}
	return fmt.Sprintf("%s %s credit limit exhausted (code=%d)", scope, limit.Window, limit.Code)
}

// APICPUCredits applies the read/write base charge and rounds each partial extra block up.
//
// POST and PUT share one case, and that is the whole point: they are the same operation as far as
// this tariff is concerned — a body arrives and the handler writes — so the two must never be able
// to disagree about what they cost. Splitting them into separate cases is what let PUT fall through
// to the error branch and be silently free.
func APICPUCredits(method string, payloadBytes int) (uint16, error) {
	if payloadBytes < 0 {
		return 0, errors.New("payload size cannot be negative")
	}
	baseCredits, extraBlockBytes := uint64(0), uint64(0)
	switch strings.ToUpper(method) {
	case "GET":
		baseCredits, extraBlockBytes = 2, 16*1024
	case "POST", "PUT":
		baseCredits, extraBlockBytes = 5, 8*1024
	default:
		return 0, fmt.Errorf("credit rate limiting does not support method %q", method)
	}
	extraBytes := uint64(0)
	if payloadBytes > creditBlockBytes {
		extraBytes = uint64(payloadBytes - creditBlockBytes)
	}
	credits := baseCredits + ceilDivide(extraBytes, extraBlockBytes)
	if credits > uint64(^uint16(0)) {
		return 0, fmt.Errorf("calculated API credits %d exceed uint16", credits)
	}
	return uint16(credits), nil
}

// APICPUBaseCredits is what a request costs before its payload is measured.
//
// It exists because a GET is charged in two steps: the byte count only exists after the handler has
// run, but the authorization verdict is needed before it. The pre-handler frame therefore carries
// the base, and a top-up follows only when the response exceeded the first free block — which for a
// GET means only when it is over 8 KB.
func APICPUBaseCredits(method string) (uint16, error) {
	return APICPUCredits(method, 0)
}

// InferenceCredits charges one credit per input block and two per output block.
func InferenceCredits(inputBytes, outputBytes int) (uint16, error) {
	if inputBytes < 0 || outputBytes < 0 {
		return 0, errors.New("inference byte sizes cannot be negative")
	}
	credits := ceilDivide(uint64(inputBytes), creditBlockBytes) +
		2*ceilDivide(uint64(outputBytes), creditBlockBytes)
	if credits > uint64(^uint16(0)) {
		return 0, fmt.Errorf("calculated inference credits %d exceed uint16", credits)
	}
	return uint16(credits), nil
}

// ChargeAPIUsage calculates and submits one HTTP request/response CPU charge, attributed to the
// route being served, and asks the daemon to authorize the caller against requiredAccess in the
// same frame.
//
// requiredAccess holds packed grants (acceso_id<<2 | nivel-1) the caller must hold at least one of.
// Empty is the common case and means no authorization is requested: an unmapped GET, a self-service
// route, or user 1, all of which the router decides before calling this.
func ChargeAPIUsage(
	ctx context.Context, companyID, userID int32, routeID int16, method string, payloadBytes int,
	requiredAccess []uint16,
) (*AccessGrant, error) {
	cpuCredits, err := APICPUCredits(method, payloadBytes)
	if err != nil {
		return nil, err
	}
	// Eligibility for the extra pool is derived here, from the same string that just chose the
	// tariff, and is not a parameter. That is the point: a caller cannot mark a write as a read by
	// disagreeing with itself, because there is only one value to disagree with.
	return chargeConfiguredCredits(ctx, companyID, userID, routeID, cpuCredits, 0, requiredAccess,
		strings.ToUpper(method) == "GET")
}

// ChargeAPIAccessOnly authorizes without charging. The credit-exempt routes use it: they skip the
// charge so a tenant out of credit can still see why, and skipping the frame with them would leave
// the mapped ones open to any session.
func ChargeAPIAccessOnly(
	ctx context.Context, companyID, userID int32, routeID int16, requiredAccess []uint16,
) (*AccessGrant, error) {
	if len(requiredAccess) == 0 {
		return nil, nil
	}
	// No credits, so nothing could come out of any pool.
	return chargeConfiguredCredits(ctx, companyID, userID, routeID, 0, 0, requiredAccess, false)
}

// ChargeAPICredits submits an already-computed credit amount. The GET top-up uses it, because the
// amount it owes is a difference between two payload sizes and not a payload size of its own.
//
// extraCreditsAllowed is a parameter here and derived in ChargeAPIUsage, because this function has
// no method to derive it from: the caller is the only one who knows what it is settling.
func ChargeAPICredits(
	ctx context.Context, companyID, userID int32, routeID int16, cpuCredits uint16,
	extraCreditsAllowed bool,
) error {
	if cpuCredits == 0 {
		return nil
	}
	// No required access, so there is no grant to hand back — only whether the charge landed.
	_, err := chargeConfiguredCredits(
		ctx, companyID, userID, routeID, cpuCredits, 0, nil, extraCreditsAllowed)
	return err
}

type creditRateLimitIdentity struct {
	companyID int32
	userID    int32
	routeID   int16
}

type creditRateLimitIdentityKey struct{}

// WithCreditRateLimitIdentity attributes nested inference calls to the authenticated API request,
// route included: what a turn spent on inference belongs to the endpoint that started it, not to a
// bucket of its own.
func WithCreditRateLimitIdentity(ctx context.Context, companyID, userID int32, routeID int16) context.Context {
	return context.WithValue(ctx, creditRateLimitIdentityKey{}, creditRateLimitIdentity{
		companyID: companyID,
		userID:    userID,
		routeID:   routeID,
	})
}

// ChargeInferenceUsage submits actual successful provider input/output bytes when identity exists.
func ChargeInferenceUsage(ctx context.Context, inputBytes, outputBytes int) error {
	identity, ok := ctx.Value(creditRateLimitIdentityKey{}).(creditRateLimitIdentity)
	if !ok {
		return nil
	}
	inferenceCredits, err := InferenceCredits(inputBytes, outputBytes)
	if err != nil {
		return err
	}
	if inferenceCredits == 0 {
		return nil
	}
	// Never eligible: the pool is CPU-only, and the daemon refuses to relax anything for a frame
	// that asks for inference.
	_, err = chargeConfiguredCredits(
		ctx, identity.companyID, identity.userID, identity.routeID, 0, inferenceCredits, nil, false,
	)
	return err
}

// IsAccessDeniedError reports whether the daemon refused the request on authorization grounds.
func IsAccessDeniedError(err error) bool {
	var denied *AccessDenied
	return errors.As(err, &denied)
}

// IsCreditRateLimitError identifies both quota exhaustion and fail-closed transport failures.
func IsCreditRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	var exceeded *CreditLimitExceeded
	return errors.As(err, &exceeded) || errors.Is(err, ErrCreditLimiterMissing) ||
		strings.Contains(err.Error(), "credit rate limiter")
}

// chargeConfiguredCredits fails closed: no authenticated decision means no API work is allowed.
// CreditExemptCompanyID is the platform operator's own company, seeded as ID 1 by fn-init. It
// runs without a credit budget: the limiter exists to meter tenants, and metering the operator
// would lock the software exactly when someone needs to get in and fix it.
//
// The exemption is from the *budget*, not from permissions. The access frame still goes out and
// is still enforced, which is the same split ChargeAPIAccessOnly already makes for the
// credit-exempt routes.
const CreditExemptCompanyID int32 = 1

func chargeConfiguredCredits(
	ctx context.Context,
	companyID, userID int32,
	routeID int16,
	cpuCredits, inferenceCredits uint16,
	requiredAccess []uint16,
	extraCreditsAllowed bool,
) (*AccessGrant, error) {
	if companyID == CreditExemptCompanyID {
		cpuCredits, inferenceCredits = 0, 0
		// Nothing left to charge and nothing to authorize: encodeCharge rejects an empty frame,
		// and sending one would turn every exempt read into a limiter error.
		if len(requiredAccess) == 0 {
			return nil, nil
		}
	}

	client := farewardClient()
	if client == nil {
		logLine("credit rate limiter not configured, refusing request::", ErrCreditLimiterMissing)
		return nil, ErrCreditLimiterMissing
	}
	accessGrant, err := client.Charge(ctx, companyID, userID, routeID, cpuCredits, inferenceCredits,
		requiredAccess, extraCreditsAllowed)
	if err != nil {
		logLine("credit rate limiter refused request::", err)
	}
	return accessGrant, err
}

// encodeCharge validates one charge and lays it out for the wire. Separate from Charge so the
// layout can be asserted without a daemon: these twenty bytes are read by offset on the Rust side
// (fareward/src/limiter/protocol.rs), and a field that shifts here charges the wrong number to
// the wrong route with nothing in either process to say so.
//
// Route zero is accepted, and means the request matched no generated route. Those credits are as
// real as any other and belong in the total; refusing them would make an unnumbered handler free.
// The ceiling it is checked against is the persisted blob's, not the route table's — see
// maxChargeRouteID.
func encodeCharge(
	companyID, userID int32, routeID int16, cpuCredits, inferenceCredits uint16,
	requiredAccess []uint16, extraCreditsAllowed bool,
) ([]byte, error) {
	if companyID <= 0 || companyID > 0xFF_FFFF || userID <= 0 || userID > 0xFF_FFFF {
		return nil, errors.New("company and user IDs must fit positive uint24")
	}
	if routeID < 0 || routeID > maxChargeRouteID {
		return nil, fmt.Errorf("route %d is outside 0..%d", routeID, maxChargeRouteID)
	}
	if len(requiredAccess) > MaxRequiredAccess {
		return nil, fmt.Errorf(
			"a route may require at most %d accesses, got %d", MaxRequiredAccess, len(requiredAccess))
	}
	// Zero terminates the slot list on the far side, so it cannot also be a grant. A zero here means
	// the caller built a packed value from acceso 0, which does not exist.
	for _, packedAccess := range requiredAccess {
		if packedAccess == 0 {
			return nil, errors.New("a required access cannot be zero")
		}
	}
	// A frame with neither is nothing to ask. Credits alone or an access alone are both valid: the
	// credit-exempt routes in main-handlers.go send authorize-only frames, which is what keeps an
	// exempt-but-mapped route from being open to any session.
	if cpuCredits == 0 && inferenceCredits == 0 && len(requiredAccess) == 0 {
		return nil, errors.New("a frame must carry credits, a required access, or both")
	}

	payload := make([]byte, creditChargePayloadSize)
	writeUint24(payload[0:3], uint32(companyID))
	writeUint24(payload[3:6], uint32(userID))
	// The flag is applied after the conversion to uint16, so the int16 parameter never has to hold
	// it: routeID stays a plain route number, validated above against maxChargeRouteID.
	encodedRoute := uint16(routeID)
	if extraCreditsAllowed {
		encodedRoute |= extraCreditFlag
	}
	binary.BigEndian.PutUint16(payload[6:8], encodedRoute)
	binary.BigEndian.PutUint16(payload[8:10], cpuCredits)
	binary.BigEndian.PutUint16(payload[10:12], inferenceCredits)
	for slot, packedAccess := range requiredAccess {
		offset := 12 + 2*slot
		binary.BigEndian.PutUint16(payload[offset:offset+2], packedAccess)
	}
	return payload, nil
}

// Charge sends one authenticated frame and returns nil only when both verdicts allow the request.
//
// The two refusals arrive in different fields: a credit violation in status, an authorization denial
// in detail. Because the daemon resolves authorization first and returns without charging on a
// refusal, the two can never both be set.
func (client *FarewardClient) Charge(
	ctx context.Context,
	companyID, userID int32,
	routeID int16,
	cpuCredits, inferenceCredits uint16,
	requiredAccess []uint16,
	extraCreditsAllowed bool,
) (*AccessGrant, error) {
	payload, err := encodeCharge(
		companyID, userID, routeID, cpuCredits, inferenceCredits, requiredAccess,
		extraCreditsAllowed)
	if err != nil {
		return nil, err
	}

	// A charge is answered without queueing, so it needs no patience beyond the round trip.
	reply, _, err := client.request(ctx, opcodeChargeCredits, payload, chargeWait(ctx), 0, 0)
	if err != nil {
		return nil, err
	}

	if reply.status != 0 {
		return nil, decodeCreditLimitResponse(reply.status)
	}
	return decodeAccessResponse(reply.detail, reply.extra, len(requiredAccess) > 0)
}

// decodeAccessResponse reads the authorization verdict out of the reply's detail field and tail.
//
// A daemon that ignored the slots would answer zero. That is treated as unavailability rather than
// as a grant: failing open here would silently unauthorize every gated route the moment the two
// binaries drifted apart.
func decodeAccessResponse(detail uint16, extra []byte, wasRequested bool) (*AccessGrant, error) {
	if !wasRequested {
		return nil, nil
	}
	switch reason := accessDeniedReason(detail & accessCodeMask); reason {
	case accessGranted:
		grant, err := decodeAccessGrant(detail, extra)
		if err != nil {
			return nil, err
		}
		return grant, nil
	case accessReasonNone, accessReasonNoUser, accessReasonStatus:
		return nil, &AccessDenied{reason: reason}
	default:
		return nil, fmt.Errorf(
			"%w: credit limiter did not answer the access check (detail %d)",
			ErrFarewardUnavailable, detail)
	}
}

// decodeAccessGrant splits the reply tail back out per slot.
//
// The two masks and the tail have to agree exactly: each slot in the has-subs mask consumes one
// MORE-terminated run, in ascending slot order, and the tail must end precisely when the last one
// does. A disagreement means the two binaries no longer share a layout, which is refused rather
// than half-read — the alternative is attributing one access's sub-accesses to another.
func decodeAccessGrant(detail uint16, extra []byte) (*AccessGrant, error) {
	grantedSlots := uint8(detail>>accessGrantedShift) & accessSlotMask
	hasSubsSlots := uint8(detail>>accessHasSubsShift) & accessSlotMask
	if hasSubsSlots&^grantedSlots != 0 {
		return nil, fmt.Errorf(
			"%w: reply marks sub-accesses on a slot it did not grant (detail %d)",
			ErrFarewardUnavailable, detail)
	}

	grant := &AccessGrant{GrantedSlots: grantedSlots}
	offset := 0
	for slotIndex := 0; slotIndex < MaxRequiredAccess; slotIndex++ {
		if hasSubsSlots&(1<<slotIndex) == 0 {
			continue
		}
		runStart := offset
		for {
			if offset >= len(extra) {
				return nil, fmt.Errorf(
					"%w: reply tail ends mid sub-access run for slot %d",
					ErrFarewardUnavailable, slotIndex)
			}
			subByte := extra[offset]
			offset++
			if subByte&subAccesoMoreBit == 0 {
				break
			}
		}
		if grant.SubAccesoBytes == nil {
			grant.SubAccesoBytes = make(map[int][]byte, 1)
		}
		grant.SubAccesoBytes[slotIndex] = extra[runStart:offset]
	}
	if offset != len(extra) {
		return nil, fmt.Errorf(
			"%w: reply tail has %d bytes left over after every marked slot",
			ErrFarewardUnavailable, len(extra)-offset)
	}
	return grant, nil
}

// chargeWait keeps a charge inside the caller's own deadline when it has one.
func chargeWait(ctx context.Context) time.Duration {
	wait := 3 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 && remaining < wait {
			return remaining
		}
	}
	return wait
}

func decodeCreditLimitResponse(code uint8) error {
	windowCode := (code >> 1) & 0b11
	// 0xFF is the daemon saying it could not answer; anything else malformed is treated the same
	// way, as unavailability rather than as a verdict.
	if code&0b1110_0000 != 0 || code&0b0001_1000 == 0 {
		return fmt.Errorf("%w: credit limiter returned status %d", ErrFarewardUnavailable, code)
	}
	windows := [...]string{"10 seconds", "1 hour", "24 hours", "month"}
	return &CreditLimitExceeded{
		Code:      code,
		Company:   code&1 == 0,
		Window:    windows[windowCode],
		Inference: code&(1<<3) != 0,
		CPU:       code&(1<<4) != 0,
	}
}

func writeUint24(target []byte, value uint32) {
	target[0], target[1], target[2] = byte(value>>16), byte(value>>8), byte(value)
}

func ceilDivide(value, divisor uint64) uint64 {
	if value == 0 {
		return 0
	}
	return 1 + (value-1)/divisor
}

func connectionDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(3 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		return contextDeadline
	}
	return deadline
}
