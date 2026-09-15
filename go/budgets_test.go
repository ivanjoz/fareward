package fareward

import (
	"testing"
)

// The payload is a colbin message, so the contract with the daemon is the field ids rather than
// byte offsets. Decoding it back is what asserts them: a field that moved to another id decodes
// as absent, which is exactly what would otherwise reach the daemon as a zero.
func TestBudgetMutationRoundTripsEveryField(t *testing.T) {
	payload, err := encodeBudgetMutation(0x123456, BudgetIncreaseCurrent, 300, 25)
	if err != nil {
		t.Fatalf("encodeBudgetMutation refused valid values: %v", err)
	}

	var decoded budgetMutationFrame
	if err := budgetMutationCodec.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	want := budgetMutationFrame{
		CompanyID: 0x123456,
		Operation: uint8(BudgetIncreaseCurrent),
		CPU:       300,
		Inference: 25,
	}
	if decoded != want {
		t.Fatalf("budget payload decoded as %+v; want %+v", decoded, want)
	}
}

// What the codec was adopted for on this shape: a mutation that names one resource does not carry
// the other at all, where the fixed layout spent eight bytes saying zero.
func TestBudgetMutationOmitsTheResourceItDoesNotName(t *testing.T) {
	cpuOnly, err := encodeBudgetMutation(7, BudgetSetDaily, 300, 0)
	if err != nil {
		t.Fatal(err)
	}
	both, err := encodeBudgetMutation(7, BudgetSetDaily, 300, 25)
	if err != nil {
		t.Fatal(err)
	}
	if len(cpuOnly) >= len(both) {
		t.Fatalf("a zero inference budget cost %d bytes against %d for a real one",
			len(cpuOnly), len(both))
	}

	var decoded budgetMutationFrame
	if err := budgetMutationCodec.Unmarshal(cpuOnly, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Inference != 0 || decoded.CPU != 300 {
		t.Fatalf("an omitted field did not decode back as zero: %+v", decoded)
	}
}

func TestBudgetMutationRejectsUnknownOperation(t *testing.T) {
	if _, err := encodeBudgetMutation(1, BudgetOperation(4), 1, 1); err == nil {
		t.Fatal("unknown budget operation was accepted")
	}
}
