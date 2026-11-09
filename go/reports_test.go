package fareward

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"
)

// The same bytes src/store/query.rs pins for the Rust encoder.
func TestReportQueryFrameMatchesTheRustVector(t *testing.T) {
	payload, err := reportQueryCodec.Append(nil, &reportQueryFrame{
		Kind: 2, CompanyID: 7, UserID: 42, First: 200_000_000, Last: 200_000_029,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x01, 0x14, 0x07, 0x24, 0x2A, 0x37, 0x00, 0xC2, 0xEB, 0x0B, 0x47, 0x1D, 0xC2, 0xEB, 0x0B}
	if !bytes.Equal(payload, want) {
		t.Fatalf("payload %#v", payload)
	}
}

// lengthPrefixed is a report reply's body as the daemon sends it: [length:u32][body].
func lengthPrefixed(body []byte) []byte {
	return binary.BigEndian.AppendUint32(nil, uint32(len(body)))
}

// answerReports makes the stub answer every report with body.
func answerReports(stub *muxDaemonStub, t *testing.T, body []byte) {
	stub.mu.Lock()
	stub.answer = func(_ uint64, opcode byte, _ []byte) (byte, []byte, bool) {
		if opcode != opcodeReport {
			t.Errorf("opcode 0x%02X", opcode)
		}
		return replyReport, append(lengthPrefixed(body), body...), true
	}
	stub.mu.Unlock()
}

// The company report src/store/query.rs builds byte for byte in
// a_company_report_carries_counters_and_credits, read back through the real reader.
func TestACompanyReportIsReadThroughTheSocket(t *testing.T) {
	stub := startMuxDaemonStub(t)
	installStubAsConfiguredFareward(t, stub)
	answerReports(stub, t, []byte{
		1, 0, 0, 0, 1,
		0x0B, 0xEB, 0xC2, 0x0A,
		0, 0, 0, 17,
		1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 4, 1, 2,
	})

	rows, err := QueryCompanyUsage(context.Background(), 7, 200_000_000, 200_000_020)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows %+v", rows)
	}
	row := rows[0]
	if row.CompanyID != 7 || row.TimeFrame != 200_000_010 ||
		row.Rejections != (Rejections{Short: 1, Long: 2, NoFunds: 3}) ||
		!bytes.Equal(row.UsedCredits, []byte{0, 4, 1, 2}) {
		t.Fatalf("row %+v", row)
	}
	frame := <-stub.frames
	if frame[0] != opcodeReport {
		t.Fatalf("sent opcode 0x%02X", frame[0])
	}
}

func TestEveryReportKindDecodes(t *testing.T) {
	stub := startMuxDaemonStub(t)
	installStubAsConfiguredFareward(t, stub)
	ctx := context.Background()

	// Kind 2: user 42, frame 5, credits blob [9].
	answerReports(stub, t, []byte{2, 0, 0, 0, 1, 0, 0, 0, 42, 0, 0, 0, 5, 0, 0, 0, 2, 1, 9})
	users, err := QueryUserUsage(ctx, 7, 0, 0, 10)
	if err != nil || len(users) != 1 || users[0].CompanyID != 7 || users[0].UserID != 42 ||
		users[0].TimeFrame != 5 || !bytes.Equal(users[0].UsedCredits, []byte{9}) {
		t.Fatalf("users %+v %v", users, err)
	}

	// Kind 3: company 3, frame 5, an empty usage value.
	answerReports(stub, t, []byte{3, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 5, 0, 0, 0, 13,
		1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	companies, err := QueryEveryCompanyUsage(ctx, 0, 10)
	if err != nil || len(companies) != 1 || companies[0].CompanyID != 3 || len(companies[0].UsedCredits) != 0 {
		t.Fatalf("companies %+v %v", companies, err)
	}

	// Kind 4: company 5 with the daily CPU at 1<<40 and the usage updated at -1.
	budget := []byte{4, 0, 0, 0, 1, 0, 0, 0, 5, 1}
	budget = binary.BigEndian.AppendUint64(budget, 1<<40) // daily_cpu
	budget = append(budget, make([]byte, 8+2+8*4+4+2+8*2+2+8*4)...)
	budget = binary.BigEndian.AppendUint32(budget, 0xFFFFFFFF) // usage_updated
	answerReports(stub, t, budget)
	budgets, err := QueryCompanyBudgets(ctx, 0)
	if err != nil || len(budgets) != 1 || budgets[0].CompanyID != 5 ||
		budgets[0].DailyCPU != 1<<40 || budgets[0].UsageUpdated != -1 {
		t.Fatalf("budgets %+v %v", budgets, err)
	}

	// Kind 5: day 100, slot 2, cpu 2345, a 1024 MB buffer pool with 37 MB dirty, and everything
	// else not measured.
	metric := []byte{5, 0, 0, 0, 1, 0, 100, 0, 2, 2, 0x09, 0x29}
	for range 10 {
		metric = append(metric, 0xFF, 0xFF)
	}
	metric = append(metric, 0x04, 0x00, 0x00, 37, 0xFF, 0xFF)
	answerReports(stub, t, metric)
	metrics, err := QueryServerMetrics(ctx, 100, 0, 101, 0)
	if err != nil || len(metrics) != 1 || metrics[0].CPUPercent != 2345 ||
		metrics[0].DatabaseCPUPercent != -1 || metrics[0].Slot != 2 ||
		metrics[0].DatabaseBufferPoolMB != 1024 || metrics[0].DatabaseDirtyMB != 37 ||
		metrics[0].DatabaseDiskGBTenths != -1 {
		t.Fatalf("metrics %+v %v", metrics, err)
	}

	// A daemon still on the eleven-column layout is refused by its version byte, not misread.
	legacy := []byte{5, 0, 0, 0, 1, 0, 100, 0, 2, 1, 0x09, 0x29}
	for range 10 {
		legacy = append(legacy, 0xFF, 0xFF)
	}
	answerReports(stub, t, legacy)
	if _, err := QueryServerMetrics(ctx, 100, 0, 101, 0); !errors.Is(err, ErrReportMalformed) {
		t.Fatalf("legacy metrics layout: %v", err)
	}
}

func TestAMalformedReportIsRefused(t *testing.T) {
	stub := startMuxDaemonStub(t)
	installStubAsConfiguredFareward(t, stub)
	ctx := context.Background()
	for name, body := range map[string][]byte{
		"wrong kind":     {2, 0, 0, 0, 0},
		"short":          {1, 0, 0, 0, 1, 0, 0},
		"left over":      {1, 0, 0, 0, 0, 7},
		"lying count":    {1, 0xFF, 0xFF, 0xFF, 0xFF},
		"unknown layout": {1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 13, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	} {
		answerReports(stub, t, body)
		if _, err := QueryCompanyUsage(ctx, 1, 0, 1); !errors.Is(err, ErrReportMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
