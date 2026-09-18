package pgproxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

// TestDataRow_InvalidLength_ReturnsError verifies malformed database rows cannot panic the proxy decoder
func TestDataRow_InvalidLength_ReturnsError(t *testing.T) {

	// Prepare and run test cases, excluding -1 because it is the valid NULL marker
	for _, test := range []struct {
		name   string
		length uint32
	}{
		{"negative-two", 0xfffffffe},
		{"minimum-int32", 0x80000000},
		{"truncated-field", 100},
	} {
		t.Run(test.name, func(t *testing.T) {

			// Verify invalid wire data is rejected without a panic
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("DataRow.Decode() panic = '%v', want = 'none'", recovered)
				}
			}()

			// Prepare unit test data containing one field with an invalid length
			data := []byte{0, 1, 0, 0, 0, 0}
			binary.BigEndian.PutUint32(data[2:], test.length)
			row := pgproto3.DataRow{}

			// Verify the malformed row is rejected
			if errDecode := row.Decode(data); errDecode == nil {
				t.Error("DataRow.Decode() error = 'nil', want = 'invalid length'")
			}
		})
	}
}

// TestDataRow_ValidValues_PreserveNullAndEmpty verifies malformed-length protection does not change valid rows
func TestDataRow_ValidValues_PreserveNullAndEmpty(t *testing.T) {

	// Prepare unit test data containing NULL, an empty value and binary data
	row := pgproto3.DataRow{Values: [][]byte{nil, {}, {0, 127, 255}}}
	data, errData := row.Encode(nil)
	if errData != nil {
		t.Fatal(errData)
	}

	// Verify the full frontend receive path preserves all three distinct values
	frontend := pgproto3.NewFrontend(bytes.NewReader(data), io.Discard)
	message, errMessage := frontend.Receive()
	if errMessage != nil {
		t.Fatal(errMessage)
	}
	decoded := message.(*pgproto3.DataRow)
	if len(decoded.Values) != 3 || decoded.Values[0] != nil || decoded.Values[1] == nil || !bytes.Equal(decoded.Values[2], row.Values[2]) {
		t.Errorf("Receive() values = '%v', want = 'NULL, empty, binary data'", decoded.Values)
	}
}

// TestCancelRequest_KeyLengths_PreserveCompleteKey verifies legacy and protocol 3.2 keys round-trip without truncation
func TestCancelRequest_KeyLengths_PreserveCompleteKey(t *testing.T) {

	// Prepare and run test cases at the legacy size and the newer protocol boundaries
	for _, length := range []int{4, 32, 256} {
		t.Run(fmt.Sprintf("%d-bytes", length), func(t *testing.T) {

			// Encode through the same Send and Flush path used by the cancellation forwarding code
			key := bytes.Repeat([]byte{0xab}, length)
			request := &pgproto3.CancelRequest{ProcessID: 123, SecretKey: key}
			var wire bytes.Buffer
			frontend := pgproto3.NewFrontend(&wire, &wire)
			frontend.Send(request)
			if errFlush := frontend.Flush(); errFlush != nil {
				t.Fatal(errFlush)
			}

			// Verify wire decoding and connection lookup use every key byte
			backend := pgproto3.NewBackend(&wire, io.Discard)
			message, errMessage := backend.ReceiveStartupMessage()
			if errMessage != nil {
				t.Fatal(errMessage)
			}
			decoded := message.(*pgproto3.CancelRequest)
			if decoded.ProcessID != request.ProcessID || !bytes.Equal(decoded.SecretKey, key) {
				t.Errorf("ReceiveStartupMessage() request = '%v', want = '%v'", decoded, request)
			}
			keyOriginal := generateKey(&pgproto3.BackendKeyData{ProcessID: 123, SecretKey: key})
			key[len(key)-1] ^= 1
			if keyOriginal == generateKey(&pgproto3.BackendKeyData{ProcessID: 123, SecretKey: key}) {
				t.Error("generateKey() different secrets = 'equal', want = 'different'")
			}
		})
	}
}
