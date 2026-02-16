package observe

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"time"
)

// This is a shared type for a span or trace id.
// It's represented by 2 uint64s and can be transformed
// to different string or int representations where needed.
type TelemetryId struct {
	lsb uint64
	msb uint64
}

var rng rand.Source

func init() {
	rng = rand.NewSource(time.Now().UnixNano())
}

// Create a new trace id
func NewTraceId() TelemetryId {
	return TelemetryId{
		msb: uint64(rng.Int63()),
		lsb: uint64(rng.Int63()),
	}
}

// Create a new span id
func NewSpanId() TelemetryId {
	return TelemetryId{
		msb: uint64(rng.Int63()),
		lsb: uint64(rng.Int63()),
	}
}

func (id TelemetryId) Msb() uint64 {
	return id.msb
}

func (id TelemetryId) Lsb() uint64 {
	return id.lsb
}

// Encode this id into an 8 byte hex (16 chars)
// Just uses the least significant of the 16 bytes
func (t TelemetryId) ToHex8() string {
	return fmt.Sprintf("%016x", t.lsb)
}

// Encode this id into a 16 byte hex (32 chars)
// Uses both 16 byte uint64 values
func (t TelemetryId) ToHex16() string {
	return fmt.Sprintf("%016x%016x", t.msb, t.lsb)
}

// Some adapters may need a raw representation
func (t TelemetryId) ToUint64() uint64 {
	return t.lsb
}

func (t *TelemetryId) FromBytes(id []byte) error {
	if len(id) != 16 {
		return errors.New("TraceID must be 16 bytes")
	}

	t.msb = binary.BigEndian.Uint64(id)
	t.lsb = binary.BigEndian.Uint64(id[8:])

	return nil
}

func (t *TelemetryId) FromString(id string) error {
	b, err := hex.DecodeString(id)
	if err != nil {
		return err
	}
	return t.FromBytes(b)
}
