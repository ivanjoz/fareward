package fareward

import (
	"encoding/binary"
	"strings"
	"testing"
)

func sampleRecord() RequestLogRecord {
	return RequestLogRecord{
		Date:      20_500,
		RequestID: 1_767_225_600_123,
		RouteID:   102,
		Frame:     41,
		CompanyID: 7,
		UserID:    42,
		ElapsedMs: 318,
		Errors: []RequestLogError{
			{ID: 1_234_567, Line: "responses.go:539", Text: "no se pudo obtener el registro"},
		},
	}
}

// The record is a colbin message, so what the daemon and this encoder agree on is the field ids,
// not byte offsets. Decoding it back is what asserts that agreement: a field that moved to a
// different id decodes as absent, and the round trip is what notices.
//
// Nothing at runtime would: the daemon would parse a plausible record out of the same bytes and
// write rows that look right and are wrong.
func TestEncodeRequestLogRoundTripsEveryField(t *testing.T) {
	record := sampleRecord()
	payload, err := encodeRequestLog(record)
	if err != nil {
		t.Fatal(err)
	}

	var decoded RequestLogRecord
	if err := requestLogCodec.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Date != 20_500 || decoded.RequestID != 1_767_225_600_123 || decoded.RouteID != 102 {
		t.Errorf("header fields decoded as %+v", decoded)
	}
	if decoded.Frame != 41 || decoded.CompanyID != 7 || decoded.UserID != 42 {
		t.Errorf("identity fields decoded as %+v", decoded)
	}
	if decoded.ElapsedMs != 318 {
		t.Errorf("elapsed = %d", decoded.ElapsedMs)
	}
	if len(decoded.Errors) != 1 {
		t.Fatalf("errors decoded as %+v", decoded.Errors)
	}
	if decoded.Errors[0] != record.Errors[0] {
		t.Errorf("error block decoded as %+v, want %+v", decoded.Errors[0], record.Errors[0])
	}
}

// The bytes the Rust test `parses_bytes_produced_by_the_go_encoder` is pinned against. Printed
// here rather than asserted so regenerating them is a copy, not a hand-assembly.
func TestEncodeRequestLogWireBytes(t *testing.T) {
	payload, err := encodeRequestLog(sampleRecord())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("sampleRecord() encodes to %d bytes: %x", len(payload), payload)
}

// The overwhelmingly common case: a request that failed at nothing. Every zero-valued field is
// absent, and so is the error list, which is most of what the codec bought on this shape.
func TestEncodeRequestLogWithNoErrors(t *testing.T) {
	record := sampleRecord()
	record.Errors = nil
	payload, err := encodeRequestLog(record)
	if err != nil {
		t.Fatal(err)
	}

	var decoded RequestLogRecord
	if err := requestLogCodec.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Errors) != 0 {
		t.Fatalf("errors decoded as %+v, want none", decoded.Errors)
	}
	if len(payload) >= 40 {
		t.Fatalf("an error-free record encoded to %d bytes", len(payload))
	}
}

// Clamping rather than refusing: a row with four of five errors is worth far more than no row.
func TestEncodeRequestLogClampsInsteadOfFailing(t *testing.T) {
	record := sampleRecord()
	record.Errors = nil
	for index := range 9 {
		record.Errors = append(record.Errors, RequestLogError{
			ID:   int32(index),
			Line: strings.Repeat("x", requestLogMaxLineBytes*2),
			Text: strings.Repeat("y", requestLogMaxTextBytes*3),
		})
	}
	original := record.Errors[0].Line

	payload, err := encodeRequestLog(record)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) > requestLogMaxPayloadSize {
		t.Fatalf("payload is %d bytes, over the %d ceiling the daemon enforces",
			len(payload), requestLogMaxPayloadSize)
	}

	var decoded RequestLogRecord
	if err := requestLogCodec.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Errors) != requestLogMaxErrors {
		t.Fatalf("error count = %d, expected the cap of %d",
			len(decoded.Errors), requestLogMaxErrors)
	}
	if len(decoded.Errors[0].Line) != requestLogMaxLineBytes {
		t.Fatalf("code line was not clamped: %d bytes", len(decoded.Errors[0].Line))
	}
	if len(decoded.Errors[0].Text) != requestLogMaxTextBytes {
		t.Fatalf("text was not clamped: %d bytes", len(decoded.Errors[0].Text))
	}
	// The caller keeps its own record intact: a log write must not shorten strings it may still
	// be using.
	if record.Errors[0].Line != original {
		t.Fatal("encoding mutated the caller's record")
	}
}

// The daemon rejects the whole frame on invalid UTF-8, so a multi-byte rune landing on the
// truncation boundary must not be cut in half — one accented character would cost the entire row.
func TestEncodeRequestLogKeepsRunesWhole(t *testing.T) {
	record := sampleRecord()
	record.Errors = []RequestLogError{{
		ID:   1,
		Line: "responses.go:539",
		Text: strings.Repeat("á", requestLogMaxTextBytes),
	}}

	payload, err := encodeRequestLog(record)
	if err != nil {
		t.Fatal(err)
	}
	var decoded RequestLogRecord
	if err := requestLogCodec.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	text := decoded.Errors[0].Text

	if len(text) > requestLogMaxTextBytes {
		t.Fatalf("text is %d bytes, over the ceiling", len(text))
	}
	if !strings.HasPrefix(record.Errors[0].Text, text) {
		t.Fatal("truncation produced something that is not a prefix of the original")
	}
	if strings.ContainsRune(text, '�') {
		t.Fatal("truncation split a rune")
	}
}

// The frame the daemon reads: opcode, a two-byte length covering only the payload, the payload,
// then the tag. The length is inside the signed bytes, so a peer cannot make the daemon buffer a
// different amount than the one that was authenticated.
func TestLengthPrefixedFrameLayout(t *testing.T) {
	nonce := [farewardNonceSize]byte{1, 2, 3, 4, 5, 6, 7, 8}
	payload, err := encodeRequestLog(sampleRecord())
	if err != nil {
		t.Fatal(err)
	}

	frame := buildFarewardFrame([]byte("test-secret"), &nonce, 0, opcodeLogRequest, payload)

	if frame[0] != opcodeLogRequest {
		t.Fatalf("opcode = %#x, expected %#x", frame[0], opcodeLogRequest)
	}
	if declared := int(binary.BigEndian.Uint16(frame[1:3])); declared != len(payload) {
		t.Fatalf("declared length %d does not match the %d-byte payload", declared, len(payload))
	}
	if len(frame) != 1+2+len(payload)+farewardAuthTagSize {
		t.Fatalf("frame is %d bytes; opcode + length + payload + tag is %d",
			len(frame), 1+2+len(payload)+farewardAuthTagSize)
	}

	signed := frame[:len(frame)-farewardAuthTagSize]
	expected := farewardAuthTag([]byte("test-secret"), &nonce, 0, signed)
	if string(frame[len(frame)-farewardAuthTagSize:]) != string(expected) {
		t.Fatal("the tag does not cover the opcode, length and payload")
	}
}
