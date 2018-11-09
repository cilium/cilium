package protocol

import (
	"bytes"
	"encoding/base64"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// QuotedValue represents a type that should be quoted when encoding
// a string value.
type QuotedValue struct {
	ValueMarshaler
}

// BoolValue provies encoding of bool for AWS protocols.
type BoolValue bool

// MarshalValue formats the value into a string for encoding.
func (v BoolValue) MarshalValue() (string, error) {
	return strconv.FormatBool(bool(v)), nil
}

// MarshalValueBuf formats the value into a byte slice for encoding.
// If there is enough room in the passed in slice v will be appended to it.
//
// Will reset the length of the passed in slice to 0.
func (v BoolValue) MarshalValueBuf(b []byte) ([]byte, error) {
	b = b[0:0]
	return strconv.AppendBool(b, bool(v)), nil
}

// BytesValue provies encoding of string for AWS protocols.
type BytesValue string

// MarshalValue formats the value into a string for encoding.
func (v BytesValue) MarshalValue() (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(v)), nil
}

// MarshalValueBuf formats the value into a byte slice for encoding.
// If there is enough room in the passed in slice v will be appended to it.
func (v BytesValue) MarshalValueBuf(b []byte) ([]byte, error) {
	m := []byte(v)

	n := base64.StdEncoding.EncodedLen(len(m))
	if len(b) < n {
		b = make([]byte, n)
	}
	base64.StdEncoding.Encode(b, m)
	return b[:n], nil
}

// StringValue provies encoding of string for AWS protocols.
type StringValue string

// MarshalValue formats the value into a string for encoding.
func (v StringValue) MarshalValue() (string, error) {
	return string(v), nil
}

// MarshalValueBuf formats the value into a byte slice for encoding.
// If there is enough room in the passed in slice v will be appended to it.
//
// Will reset the length of the passed in slice to 0.
func (v StringValue) MarshalValueBuf(b []byte) ([]byte, error) {
	b = b[0:0]
	return append(b, v...), nil
}

// Int64Value provies encoding of int64 for AWS protocols.
type Int64Value int64

// MarshalValue formats the value into a string for encoding.
func (v Int64Value) MarshalValue() (string, error) {
	return strconv.FormatInt(int64(v), 10), nil
}

// MarshalValueBuf formats the value into a byte slice for encoding.
// If there is enough room in the passed in slice v will be appended to it.
//
// Will reset the length of the passed in slice to 0.
func (v Int64Value) MarshalValueBuf(b []byte) ([]byte, error) {
	b = b[0:0]
	return strconv.AppendInt(b, int64(v), 10), nil
}

// Float64Value provies encoding of float64 for AWS protocols.
type Float64Value float64

// MarshalValue formats the value into a string for encoding.
func (v Float64Value) MarshalValue() (string, error) {
	return strconv.FormatFloat(float64(v), 'f', -1, 64), nil
}

// MarshalValueBuf formats the value into a byte slice for encoding.
// If there is enough room in the passed in slice v will be appended to it.
//
// Will reset the length of the passed in slice to 0.
func (v Float64Value) MarshalValueBuf(b []byte) ([]byte, error) {
	b = b[0:0]
	return strconv.AppendFloat(b, float64(v), 'f', -1, 64), nil
}

// JSONValue provies encoding of aws.JSONValues for AWS protocols.
type JSONValue struct {
	V          aws.JSONValue
	EscapeMode EscapeMode
}

// MarshalValue formats the value into a string for encoding.
func (v JSONValue) MarshalValue() (string, error) {
	return EncodeJSONValue(v.V, v.EscapeMode)
}

// MarshalValueBuf formats the value into a byte slice for encoding.
// If there is enough room in the passed in slice v will be appended to it.
//
// Will reset the length of the passed in slice to 0.
func (v JSONValue) MarshalValueBuf(b []byte) ([]byte, error) {
	b = b[0:0]

	m, err := EncodeJSONValue(v.V, v.EscapeMode)
	if err != nil {
		return nil, err
	}

	return append(b, []byte(m)...), nil
}

// Time formats for protocol time fields.
const (
	ISO8601TimeFormat = "2006-01-02T15:04:05Z"         // ISO 8601 formated time.
	RFC822TimeFromat  = "Mon, 2 Jan 2006 15:04:05 GMT" // RFC822 formatted time.
	UnixTimeFormat    = "unix time format"             // Special case for Unix time
)

// TimeValue provies encoding of time.Time for AWS protocols.
type TimeValue struct {
	V      time.Time
	Format string
}

// MarshalValue formats the value into a string givin a format for encoding.
func (v TimeValue) MarshalValue() (string, error) {
	t := time.Time(v.V)

	if v.Format == UnixTimeFormat {
		return strconv.FormatInt(t.UTC().Unix(), 10), nil
	}
	return t.UTC().Format(v.Format), nil
}

// MarshalValueBuf formats the value into a byte slice for encoding.
// If there is enough room in the passed in slice v will be appended to it.
//
// Will reset the length of the passed in slice to 0.
func (v TimeValue) MarshalValueBuf(b []byte) ([]byte, error) {
	b = b[0:0]

	m, err := v.MarshalValue()
	if err != nil {
		return nil, err
	}

	return append(b, m...), nil
}

// A ReadSeekerStream wrapps an io.ReadSeeker to be used as a StreamMarshaler.
type ReadSeekerStream struct {
	V io.ReadSeeker
}

// MarshalStream returns the wrapped io.ReadSeeker for encoding.
func (v ReadSeekerStream) MarshalStream() (io.ReadSeeker, error) {
	return v.V, nil
}

// A BytesStream aliases a byte slice to be used as a StreamMarshaler.
type BytesStream []byte

// MarshalStream marshals a byte slice into an io.ReadSeeker for encoding.
func (v BytesStream) MarshalStream() (io.ReadSeeker, error) {
	return bytes.NewReader([]byte(v)), nil
}

// A StringStream aliases a string to be used as a StreamMarshaler.
type StringStream string

// MarshalStream marshals a string into an io.ReadSeeker for encoding.
func (v StringStream) MarshalStream() (io.ReadSeeker, error) {
	return strings.NewReader(string(v)), nil
}
