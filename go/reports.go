package fareward

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ivanjoz/colbin"
)

// Reports: how the backend reads usage, budgets and server metrics now that the daemon is their
// source of truth (fareward plan D7). Opcode 0x09; mirrored by src/store/query.rs.
//
// The reply is shape 0x0B, [length:u32][body], and the body is [kind:u8][rows:u32][row…],
// big-endian throughout. Each row carries a value in the daemon's own store layout
// (src/store/codec.rs), which is what this file decodes.
//
// Reports read what the daemon has flushed, so they lag the limiter by at most one flush interval
// (15 s by default), as the database rows they replace did.

// reportQueryFrame is opcode 0x09 on the wire. Mirrors ReportQueryFrame in
// fareward/src/store/query.rs, field id for field id.
type reportQueryFrame struct {
	Kind      uint8 `cb:"1"`
	CompanyID int32 `cb:"2"`
	UserID    int32 `cb:"3"`
	First     int64 `cb:"4"`
	Last      int64 `cb:"5"`
}

var reportQueryCodec = colbin.MustCodec[reportQueryFrame]()

const (
	reportKindCompanyUsage      = uint8(1)
	reportKindUserUsage         = uint8(2)
	reportKindEveryCompanyUsage = uint8(3)
	reportKindBudgets           = uint8(4)
	reportKindServerMetrics     = uint8(5)

	// reportBodySize is what replyBodySize answers for a report: not a width but a marker that the
	// body states its own length in four bytes.
	reportBodySize = -2
	// maxReportBytes mirrors MAX_REPORT_BYTES, with room for the head: a longer length is a broken
	// stream, not a big report, and is refused before anything is allocated.
	maxReportBytes = 32<<20 + 1024

	reportWait = 10 * time.Second

	// companyUsageHead is a usage_company value up to its credits blob: version and three counters.
	companyUsageHead  = 1 + 3*4
	storeValueVersion = byte(1)
)

// ErrReportMalformed means the daemon answered a report this client cannot read: the two binaries
// no longer share a layout.
var ErrReportMalformed = errors.New("fareward report is malformed")

// Rejections are a company's refusals in one time frame, by cause (fareward plan D9).
type Rejections struct {
	// Short is the short-window gate and Long the long-window gate (their lengths are the daemon's
	// rate_limit.short_window_seconds and long_window_minutes): signs of abuse.
	Short uint32
	Long  uint32
	// NoFunds is the daily entitlement, the monthly ceiling or an extra pool that could not pay.
	NoFunds uint32
}

// CompanyUsageRow is one company's usage in one time frame. UsedCredits is the per-route credits
// blob (src/limiter/credits_blob.rs), unchanged from what the database column held.
type CompanyUsageRow struct {
	CompanyID   int32
	TimeFrame   int32
	Rejections  Rejections
	UsedCredits []byte
}

// UserUsageRow is one user's usage in one time frame.
type UserUsageRow struct {
	CompanyID   int32
	UserID      int32
	TimeFrame   int32
	UsedCredits []byte
}

// CompanyBudget is one company's entitlement and the usage counters the daemon last flushed,
// field for field what company_credit_budget held.
type CompanyBudget struct {
	CompanyID               int32
	DailyCPU                uint64
	DailyInference          uint64
	BudgetMonthStartDay     int16
	MonthlyCPUCeiling       uint64
	MonthlyInferenceCeiling uint64
	LastSetCPU              uint64
	LastSetInference        uint64
	Updated                 int32
	UsageDayPeriod          int16
	DayCPUUsed              uint64
	DayInferenceUsed        uint64
	UsageMonthStartDay      int16
	MonthCPUUsed            uint64
	MonthInferenceUsed      uint64
	DayExtraCPUUsed         uint64
	MonthExtraCPUUsed       uint64
	UsageUpdated            int32
}

// ServerMetricRow is one five-second window: the peak of each column, -1 when not measured.
// Percentages are hundredths, rates are 5 KB/s units, memory is MB.
type ServerMetricRow struct {
	Date               int16
	Slot               int16
	CPUPercent         int16
	MemPercent         int16
	DiskPercent        int16
	NetRxRate          int16
	NetTxRate          int16
	BackendMemMB       int16
	BackendCPUPercent  int16
	FarewardMemMB      int16
	FarewardCPUPercent int16
	DatabaseMemMB      int16
	DatabaseCPUPercent int16
}

// QueryCompanyUsage reads one company's rows over the time frames [first, last]. Company 0 is the
// platform-wide aggregate.
func QueryCompanyUsage(ctx context.Context, companyID, first, last int32) ([]CompanyUsageRow, error) {
	body, err := report(ctx, reportQueryFrame{
		Kind: reportKindCompanyUsage, CompanyID: companyID, First: int64(first), Last: int64(last),
	})
	if err != nil {
		return nil, err
	}
	return decodeCompanyUsageRows(body, reportKindCompanyUsage, companyID)
}

// QueryEveryCompanyUsage reads every company's rows over [first, last], the platform aggregate
// (company 0) included.
func QueryEveryCompanyUsage(ctx context.Context, first, last int32) ([]CompanyUsageRow, error) {
	body, err := report(ctx, reportQueryFrame{
		Kind: reportKindEveryCompanyUsage, First: int64(first), Last: int64(last),
	})
	if err != nil {
		return nil, err
	}
	return decodeCompanyUsageRows(body, reportKindEveryCompanyUsage, 0)
}

// QueryUserUsage reads one user's rows over [first, last], or every user of the company when
// userID is 0.
func QueryUserUsage(ctx context.Context, companyID, userID, first, last int32) ([]UserUsageRow, error) {
	body, err := report(ctx, reportQueryFrame{
		Kind: reportKindUserUsage, CompanyID: companyID, UserID: userID,
		First: int64(first), Last: int64(last),
	})
	if err != nil {
		return nil, err
	}
	reader, rows, err := openReport(body, reportKindUserUsage)
	if err != nil {
		return nil, err
	}
	out := make([]UserUsageRow, 0, rows)
	for range rows {
		row := UserUsageRow{CompanyID: companyID, UserID: reader.i32(), TimeFrame: reader.i32()}
		value := reader.value()
		if reader.err == nil {
			if len(value) < 1 || value[0] != storeValueVersion {
				return nil, fmt.Errorf("%w: usage_user value layout", ErrReportMalformed)
			}
			row.UsedCredits = value[1:]
		}
		out = append(out, row)
	}
	return out, reader.finish()
}

// QueryCompanyBudgets reads one company's budget, or every company's when companyID is 0. A
// company that never had a budget set and never charged anything has no row.
func QueryCompanyBudgets(ctx context.Context, companyID int32) ([]CompanyBudget, error) {
	body, err := report(ctx, reportQueryFrame{Kind: reportKindBudgets, CompanyID: companyID})
	if err != nil {
		return nil, err
	}
	reader, rows, err := openReport(body, reportKindBudgets)
	if err != nil {
		return nil, err
	}
	out := make([]CompanyBudget, 0, rows)
	for range rows {
		budget := CompanyBudget{CompanyID: reader.i32()}
		if reader.byte() != storeValueVersion && reader.err == nil {
			return nil, fmt.Errorf("%w: budget value layout", ErrReportMalformed)
		}
		budget.DailyCPU = reader.u64()
		budget.DailyInference = reader.u64()
		budget.BudgetMonthStartDay = reader.i16()
		budget.MonthlyCPUCeiling = reader.u64()
		budget.MonthlyInferenceCeiling = reader.u64()
		budget.LastSetCPU = reader.u64()
		budget.LastSetInference = reader.u64()
		budget.Updated = reader.i32()
		budget.UsageDayPeriod = reader.i16()
		budget.DayCPUUsed = reader.u64()
		budget.DayInferenceUsed = reader.u64()
		budget.UsageMonthStartDay = reader.i16()
		budget.MonthCPUUsed = reader.u64()
		budget.MonthInferenceUsed = reader.u64()
		budget.DayExtraCPUUsed = reader.u64()
		budget.MonthExtraCPUUsed = reader.u64()
		budget.UsageUpdated = reader.i32()
		out = append(out, budget)
	}
	return out, reader.finish()
}

// QueryServerMetrics reads the windows from (firstDate, firstSlot) to (lastDate, lastSlot), in
// time order. A date is a UTC unix day and a slot its five-second window, 0..17279.
func QueryServerMetrics(
	ctx context.Context, firstDate, firstSlot, lastDate, lastSlot int16,
) ([]ServerMetricRow, error) {
	pack := func(date, slot int16) int64 { return int64(date)<<16 | int64(uint16(slot)) }
	body, err := report(ctx, reportQueryFrame{
		Kind: reportKindServerMetrics, First: pack(firstDate, firstSlot), Last: pack(lastDate, lastSlot),
	})
	if err != nil {
		return nil, err
	}
	reader, rows, err := openReport(body, reportKindServerMetrics)
	if err != nil {
		return nil, err
	}
	out := make([]ServerMetricRow, 0, rows)
	for range rows {
		row := ServerMetricRow{Date: reader.i16(), Slot: reader.i16()}
		if reader.byte() != storeValueVersion && reader.err == nil {
			return nil, fmt.Errorf("%w: server_metrics value layout", ErrReportMalformed)
		}
		for _, field := range []*int16{
			&row.CPUPercent, &row.MemPercent, &row.DiskPercent, &row.NetRxRate, &row.NetTxRate,
			&row.BackendMemMB, &row.BackendCPUPercent, &row.FarewardMemMB, &row.FarewardCPUPercent,
			&row.DatabaseMemMB, &row.DatabaseCPUPercent,
		} {
			*field = reader.i16()
		}
		out = append(out, row)
	}
	return out, reader.finish()
}

func report(ctx context.Context, frame reportQueryFrame) ([]byte, error) {
	client := farewardClient()
	if client == nil {
		return nil, ErrCreditLimiterMissing
	}
	payload, err := reportQueryCodec.Append(nil, &frame)
	if err != nil {
		return nil, fmt.Errorf("encode report query: %w", err)
	}
	reply, err := client.requestOnce(ctx, opcodeReport, payload, reportWait)
	if err != nil {
		return nil, err
	}
	if reply.shape != replyReport {
		return nil, fmt.Errorf("%w: report answered with shape 0x%02X",
			ErrFarewardUnavailable, reply.shape)
	}
	return reply.body, nil
}

// readReportBody reads a report reply's [length:u32][body] off the socket.
func readReportBody(conn io.Reader) ([]byte, error) {
	length := [4]byte{}
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(length[:])
	if size > maxReportBytes {
		return nil, fmt.Errorf("fareward report declares %d bytes, over the %d ceiling",
			size, maxReportBytes)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

func decodeCompanyUsageRows(body []byte, kind uint8, companyID int32) ([]CompanyUsageRow, error) {
	reader, rows, err := openReport(body, kind)
	if err != nil {
		return nil, err
	}
	out := make([]CompanyUsageRow, 0, rows)
	for range rows {
		row := CompanyUsageRow{CompanyID: companyID}
		if kind == reportKindEveryCompanyUsage {
			row.CompanyID = reader.i32()
		}
		row.TimeFrame = reader.i32()
		value := reader.value()
		if reader.err == nil {
			if len(value) < companyUsageHead || value[0] != storeValueVersion {
				return nil, fmt.Errorf("%w: usage_company value layout", ErrReportMalformed)
			}
			row.Rejections = Rejections{
				Short:   binary.BigEndian.Uint32(value[1:5]),
				Long:    binary.BigEndian.Uint32(value[5:9]),
				NoFunds: binary.BigEndian.Uint32(value[9:13]),
			}
			row.UsedCredits = value[companyUsageHead:]
		}
		out = append(out, row)
	}
	return out, reader.finish()
}

// openReport checks the head and returns a reader positioned on the first row. The row count is
// bounded by the body, so a lying count cannot make the caller allocate past what arrived.
func openReport(body []byte, kind uint8) (*reportReader, int, error) {
	if len(body) < 5 || body[0] != kind {
		return nil, 0, fmt.Errorf("%w: expected kind %d", ErrReportMalformed, kind)
	}
	rows := int(binary.BigEndian.Uint32(body[1:5]))
	if rows > len(body) {
		return nil, 0, fmt.Errorf("%w: %d rows in %d bytes", ErrReportMalformed, rows, len(body))
	}
	return &reportReader{body: body, offset: 5}, rows, nil
}

// reportReader reads big-endian fields and remembers the first overrun, so a decoder reads a
// whole row and checks once.
type reportReader struct {
	body   []byte
	offset int
	err    error
}

func (reader *reportReader) take(size int) []byte {
	if reader.err != nil {
		return nil
	}
	if size < 0 || len(reader.body)-reader.offset < size {
		reader.err = fmt.Errorf("%w: ends mid row", ErrReportMalformed)
		return nil
	}
	field := reader.body[reader.offset : reader.offset+size]
	reader.offset += size
	return field
}

func (reader *reportReader) byte() byte {
	if field := reader.take(1); field != nil {
		return field[0]
	}
	return 0
}

func (reader *reportReader) i16() int16 {
	if field := reader.take(2); field != nil {
		return int16(binary.BigEndian.Uint16(field))
	}
	return 0
}

func (reader *reportReader) i32() int32 {
	if field := reader.take(4); field != nil {
		return int32(binary.BigEndian.Uint32(field))
	}
	return 0
}

func (reader *reportReader) u64() uint64 {
	if field := reader.take(8); field != nil {
		return binary.BigEndian.Uint64(field)
	}
	return 0
}

// value reads a [len:u32][bytes] run.
func (reader *reportReader) value() []byte {
	length := reader.take(4)
	if length == nil {
		return nil
	}
	return reader.take(int(binary.BigEndian.Uint32(length)))
}

// finish fails on an overrun or on bytes left over after the last row.
func (reader *reportReader) finish() error {
	if reader.err != nil {
		return reader.err
	}
	if reader.offset != len(reader.body) {
		return fmt.Errorf("%w: %d bytes after the last row", ErrReportMalformed,
			len(reader.body)-reader.offset)
	}
	return nil
}
