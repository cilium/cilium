package protocol

import (
	"io"
)

// A FieldMarshaler interface is used to marshal struct fields when encoding.
type FieldMarshaler interface {
	MarshalFields(FieldEncoder) error
}

// FieldMarshalerFunc is a helper utility that wrapps a function and allows
// that function to be called as a FieldMarshaler.
type FieldMarshalerFunc func(FieldEncoder) error

// MarshalFields will call the underlying function passing in the field encoder
// with the protocol field encoder.
func (fn FieldMarshalerFunc) MarshalFields(e FieldEncoder) error {
	return fn(e)
}

// ValueMarshaler provides a generic type for all encoding field values to be
// passed into a encoder's methods with.
type ValueMarshaler interface {
	MarshalValue() (string, error)
	MarshalValueBuf([]byte) ([]byte, error)
}

// A StreamMarshaler interface is used to marshal a stream when encoding.
type StreamMarshaler interface {
	MarshalStream() (io.ReadSeeker, error)
}

// MarshalListValues is a marshaler for list encoders.
type MarshalListValues interface {
	MarshalValues(enc ListEncoder) error
}

// MapMarshaler is a marshaler for map encoders.
type MapMarshaler interface {
	MarshalValues(enc MapEncoder) error
}

// A ListEncoder provides the interface for encoders that will encode List elements.
type ListEncoder interface {
	Start()
	End()

	Map() MapEncoder
	List() ListEncoder

	ListAddValue(v ValueMarshaler)
	ListAddFields(m FieldMarshaler)
}

// A MapEncoder provides the interface for encoders that will encode map elements.
type MapEncoder interface {
	Start()
	End()

	Map(k string) MapEncoder
	List(k string) ListEncoder

	MapSetValue(k string, v ValueMarshaler)
	MapSetFields(k string, m FieldMarshaler)
}

// A FieldEncoder provides the interface for encoding struct field members.
type FieldEncoder interface {
	SetValue(t Target, k string, m ValueMarshaler, meta Metadata)
	SetStream(t Target, k string, m StreamMarshaler, meta Metadata)
	SetFields(t Target, k string, m FieldMarshaler, meta Metadata)

	Map(t Target, k string, meta Metadata) MapEncoder
	List(t Target, k string, meta Metadata) ListEncoder
}

// A FieldBuffer provides buffering of fields so the number of
// allocations are reduced by providng a persistent buffer that is
// used between fields.
type FieldBuffer struct {
	buf []byte
}

// GetValue will retrieve the ValueMarshaler's value by appending the
// value to the buffer. Will return the buffer that was populated.
//
// This buffer is only valid until the next time GetValue is called.
func (b *FieldBuffer) GetValue(m ValueMarshaler) ([]byte, error) {
	v, err := m.MarshalValueBuf(b.buf)
	if len(v) > len(b.buf) {
		b.buf = v
	}
	return v, err
}
