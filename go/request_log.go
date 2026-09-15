package fareward

import (
	"context"
	"errors"

	"github.com/ivanjoz/colbin"
)

// Opcode 0x04: the end-of-request record.
//
// The one frame the daemon never answers: making a response wait for an acknowledgement that a log
// was stored would put the daemon's latency on the critical path of every request in the system.
// The client writes the frame and returns.
//
//	[opcode:1][length:u16][payload:length][tag:8]
//
// The record is a colbin message, mirrored by `RequestLogRecord` in fareward/src/reqlog/protocol.rs.
// It is the shape that gained most from the codec: an error-free row — the overwhelming majority —
// writes only the fields it actually set, and the daemon's side lost a hand-written parser with
// three length idioms and seven ways to be lied to about a length.

const (
	// The daemon enforces the same two ceilings and refuses anything past them, so these are a
	// contract and not a local preference. The error cap is enforced on both sides too.
	requestLogMaxErrors    = 4
	requestLogMaxLineBytes = 64
	requestLogMaxTextBytes = 200

	// Matches REQUEST_LOG_MAX_PAYLOAD_SIZE in fareward/src/reqlog/protocol.rs, which is what the
	// daemon will buffer before checking a tag.
	requestLogMaxPayloadSize = 64 + requestLogMaxErrors*300
)

// RequestLogError is one failing code line, already hashed by the caller.
type RequestLogError struct {
	ID   int32  `cb:"1"`
	Line string `cb:"2"`
	Text string `cb:"3"`
}

// RequestLogRecord is everything one finished request contributes to user_logs.
type RequestLogRecord struct {
	Date      int16             `cb:"1"`
	RequestID int64             `cb:"2"`
	RouteID   int16             `cb:"3"`
	Frame     uint8             `cb:"4"`
	CompanyID int32             `cb:"5"`
	UserID    int32             `cb:"6"`
	ElapsedMs int16             `cb:"7"`
	Errors    []RequestLogError `cb:"8"`
}

var requestLogCodec = colbin.MustCodec[RequestLogRecord]()

var (
	ErrRequestLogTooLarge = errors.New("request log payload exceeds the protocol ceiling")
	// ErrRequestLogNotConfigured means no daemon address was installed at startup — a local run
	// without fareward, most often. Requests still work; they simply leave no row.
	ErrRequestLogNotConfigured = errors.New("fareward client is not configured")
)

// SendRequestLog writes one record and returns without waiting for anything.
//
// It reports an error only when the frame could not be written at all, and every caller ignores
// it beyond logging: a request that has already produced its response must not fail because its
// log row did not land.
func SendRequestLog(ctx context.Context, record RequestLogRecord) error {
	client := farewardClient()
	if client == nil {
		return ErrRequestLogNotConfigured
	}
	payload, err := encodeRequestLog(record)
	if err != nil {
		return err
	}
	return client.send(ctx, opcodeLogRequest, payload)
}

// encodeRequestLog builds the payload, clamping rather than refusing.
//
// A record that violates a ceiling is still worth writing without the part that violated it: an
// over-long preview truncated to 200 bytes still says what happened, and a fifth error dropped
// still leaves four. Refusing outright would throw away the row over its least important field.
func encodeRequestLog(record RequestLogRecord) ([]byte, error) {
	// Clamped into a copy rather than in place: the caller's record is its own, and a log write
	// must not quietly shorten the strings a caller may still be using.
	if len(record.Errors) > requestLogMaxErrors {
		record.Errors = record.Errors[:requestLogMaxErrors]
	}
	clamped := make([]RequestLogError, len(record.Errors))
	for index, requestError := range record.Errors {
		clamped[index] = RequestLogError{
			ID:   requestError.ID,
			Line: truncateUTF8(requestError.Line, requestLogMaxLineBytes),
			Text: truncateUTF8(requestError.Text, requestLogMaxTextBytes),
		}
	}
	record.Errors = clamped

	payload := requestLogCodec.Append(nil, &record)
	// Unreachable given the clamping above; kept because the daemon closes the connection on an
	// oversized declared length, and a silent framing bug here would take the charges and locks
	// on that connection down with it.
	if len(payload) > requestLogMaxPayloadSize {
		return nil, ErrRequestLogTooLarge
	}
	return payload, nil
}

// truncateUTF8 cuts to at most limit bytes without splitting a rune. A half rune would travel as
// invalid UTF-8 and the daemon would refuse the whole frame over one character.
func truncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	cut := limit
	// Continuation bytes are 10xxxxxx; back up to the start of the rune they belong to.
	for cut > 0 && value[cut]&0xC0 == 0x80 {
		cut--
	}
	return value[:cut]
}
