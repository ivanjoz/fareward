package fareward

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ivanjoz/colbin"
)

// budgetMutationFrame is opcode 0x05 on the wire. Mirrored by `BudgetMutation` in
// fareward/src/limiter/budget.rs, field id for field id.
//
// Both credit figures are almost always small, and colbin writes an integer in the bytes it needs
// rather than in the eight the type declares — which is what turns a fixed twenty-byte payload
// into nine. A zero field is not written at all, so `SetDaily` of a CPU budget alone carries no
// inference field.
type budgetMutationFrame struct {
	CompanyID int32  `cb:"1"`
	Operation uint8  `cb:"2"`
	CPU       uint64 `cb:"3"`
	Inference uint64 `cb:"4"`
}

var budgetMutationCodec = colbin.MustCodec[budgetMutationFrame]()

type BudgetOperation uint8

const (
	BudgetSetDaily        BudgetOperation = 1
	BudgetSetCurrent      BudgetOperation = 2
	BudgetIncreaseCurrent BudgetOperation = 3
)

var (
	ErrBudgetMonthNotConfigured = errors.New("company credit budget is not configured for the current month")
	ErrBudgetMutationOverflow   = errors.New("company credit budget overflow")
)

func MutateCompanyCreditBudget(
	ctx context.Context,
	companyID int32,
	operation BudgetOperation,
	cpuCredits, inferenceCredits uint64,
) error {
	client := farewardClient()
	if client == nil {
		return ErrCreditLimiterMissing
	}
	payload, err := encodeBudgetMutation(companyID, operation, cpuCredits, inferenceCredits)
	if err != nil {
		return err
	}
	reply, err := client.requestOnce(ctx, opcodeMutateCompanyBudget, payload, 3*time.Second)
	if err != nil {
		return err
	}
	switch reply.shape {
	case replyAck:
		return nil
	case replyBudgetRefused:
		switch reply.body[0] {
		case 1:
			return ErrBudgetMonthNotConfigured
		case 2:
			return ErrBudgetMutationOverflow
		}
		return fmt.Errorf("%w: budget mutation refused with reason %d",
			ErrFarewardUnavailable, reply.body[0])
	default:
		return fmt.Errorf("%w: budget mutation answered with shape 0x%02X",
			ErrFarewardUnavailable, reply.shape)
	}
}

func encodeBudgetMutation(
	companyID int32,
	operation BudgetOperation,
	cpuCredits, inferenceCredits uint64,
) ([]byte, error) {
	if companyID <= 0 || companyID > 0xFF_FFFF {
		return nil, errors.New("company ID must fit positive uint24")
	}
	if operation < BudgetSetDaily || operation > BudgetIncreaseCurrent {
		return nil, fmt.Errorf("unknown budget operation %d", operation)
	}
	if cpuCredits > uint64(^uint64(0)>>1) || inferenceCredits > uint64(^uint64(0)>>1) {
		return nil, errors.New("credit budget values must fit int64")
	}
	return budgetMutationCodec.Append(nil, &budgetMutationFrame{
		CompanyID: companyID,
		Operation: uint8(operation),
		CPU:       cpuCredits,
		Inference: inferenceCredits,
	}), nil
}
