// Copyright 2012, Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sqltypes implements interfaces and types that represent SQL values.
package sqltypes

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/youtube/vitess/go/hack"

	querypb "github.com/youtube/vitess/go/vt/proto/query"
)

var (
	// NULL represents the NULL value.
	NULL = Value{}
	// DontEscape tells you if a character should not be escaped.
	DontEscape = byte(255)
	nullstr    = []byte("null")
)

// BinWriter interface is used for encoding values.
// Types like bytes.Buffer conform to this interface.
// We expect the writer objects to be in-memory buffers.
// So, we don't expect the write operations to fail.
type BinWriter interface {
	Write([]byte) (int, error)
	WriteByte(byte) error
}

// Value can store any SQL value. If the value represents
// an integral type, the bytes are always stored as a cannonical
// representation that matches how MySQL returns such values.
type Value struct {
	typ querypb.Type
	val []byte
}

// MakeTrusted makes a new Value based on the type.
// If the value is an integral, then val must be in its cannonical
// form. This function should only be used if you know the value
// and type conform to the rules.  Every place this function is
// called, a comment is needed that explains why it's justified.
// Functions within this package are exempt.
func MakeTrusted(typ querypb.Type, val []byte) Value {
	if typ == Null {
		return NULL
	}
	return Value{typ: typ, val: val}
}

// MakeString makes a VarBinary Value.
func MakeString(val []byte) Value {
	return MakeTrusted(VarBinary, val)
}

// BuildValue builds a value from any go type. sqltype.Value is
// also allowed.
func BuildValue(goval interface{}) (v Value, err error) {
	// Look for the most common types first.
	switch goval := goval.(type) {
	case nil:
		// no op
	case []byte:
		v = MakeTrusted(VarBinary, goval)
	case int64:
		v = MakeTrusted(Int64, strconv.AppendInt(nil, int64(goval), 10))
	case uint64:
		v = MakeTrusted(Uint64, strconv.AppendUint(nil, uint64(goval), 10))
	case float64:
		v = MakeTrusted(Float64, strconv.AppendFloat(nil, goval, 'f', -1, 64))
	case int:
		v = MakeTrusted(Int64, strconv.AppendInt(nil, int64(goval), 10))
	case int8:
		v = MakeTrusted(Int8, strconv.AppendInt(nil, int64(goval), 10))
	case int16:
		v = MakeTrusted(Int16, strconv.AppendInt(nil, int64(goval), 10))
	case int32:
		v = MakeTrusted(Int32, strconv.AppendInt(nil, int64(goval), 10))
	case uint:
		v = MakeTrusted(Uint64, strconv.AppendUint(nil, uint64(goval), 10))
	case uint8:
		v = MakeTrusted(Uint8, strconv.AppendUint(nil, uint64(goval), 10))
	case uint16:
		v = MakeTrusted(Uint16, strconv.AppendUint(nil, uint64(goval), 10))
	case uint32:
		v = MakeTrusted(Uint32, strconv.AppendUint(nil, uint64(goval), 10))
	case float32:
		v = MakeTrusted(Float32, strconv.AppendFloat(nil, float64(goval), 'f', -1, 64))
	case string:
		v = MakeTrusted(VarBinary, []byte(goval))
	case time.Time:
		v = MakeTrusted(Datetime, []byte(goval.Format("2006-01-02 15:04:05")))
	case Value:
		v = goval
	case *querypb.BindVariable:
		return ValueFromBytes(goval.Type, goval.Value)
	default:
		return v, fmt.Errorf("unexpected type %T: %v", goval, goval)
	}
	return v, nil
}

// BuildConverted is like BuildValue except that it tries to
// convert a string or []byte to an integral if the target type
// is an integral. We don't perform other implicit conversions
// because they're unsafe.
func BuildConverted(typ querypb.Type, goval interface{}) (v Value, err error) {
	if IsIntegral(typ) {
		switch goval := goval.(type) {
		case []byte:
			return ValueFromBytes(typ, goval)
		case string:
			return ValueFromBytes(typ, []byte(goval))
		case Value:
			if goval.IsQuoted() {
				return ValueFromBytes(typ, goval.Raw())
			}
		case *querypb.BindVariable:
			if IsQuoted(goval.Type) {
				return ValueFromBytes(typ, goval.Value)
			}
		}
	}
	return BuildValue(goval)
}

// ValueFromBytes builds a Value using typ and val. It ensures that val
// matches the requested type. If type is an integral it's converted to
// a cannonical form. Otherwise, the original representation is preserved.
func ValueFromBytes(typ querypb.Type, val []byte) (v Value, err error) {
	switch {
	case IsSigned(typ):
		signed, err := strconv.ParseInt(string(val), 0, 64)
		if err != nil {
			return NULL, err
		}
		v = MakeTrusted(typ, strconv.AppendInt(nil, signed, 10))
	case IsUnsigned(typ):
		unsigned, err := strconv.ParseUint(string(val), 0, 64)
		if err != nil {
			return NULL, err
		}
		v = MakeTrusted(typ, strconv.AppendUint(nil, unsigned, 10))
	case typ == Tuple:
		return NULL, errors.New("tuple not allowed for ValueFromBytes")
	case IsFloat(typ) || typ == Decimal:
		_, err := strconv.ParseFloat(string(val), 64)
		if err != nil {
			return NULL, err
		}
		// After verification, we preserve the original representation.
		fallthrough
	default:
		v = MakeTrusted(typ, val)
	}
	return v, nil
}

// BuildIntegral builds an integral type from a string representaion.
// The type will be Int64 or Uint64. Int64 will be preferred where possible.
func BuildIntegral(val string) (n Value, err error) {
	signed, err := strconv.ParseInt(val, 0, 64)
	if err == nil {
		return MakeTrusted(Int64, strconv.AppendInt(nil, signed, 10)), nil
	}
	unsigned, err := strconv.ParseUint(val, 0, 64)
	if err != nil {
		return Value{}, err
	}
	return MakeTrusted(Uint64, strconv.AppendUint(nil, unsigned, 10)), nil
}

// Type returns the type of Value.
func (v Value) Type() querypb.Type {
	return v.typ
}

// Raw returns the raw bytes. All types are currently implemented as []byte.
// You should avoid using this function. If you do, you should treat the
// bytes as read-only.
func (v Value) Raw() []byte {
	return v.val
}

// Len returns the length.
func (v Value) Len() int {
	return len(v.val)
}

// String returns the raw value as a string.
func (v Value) String() string {
	return hack.String(v.val)
}

// ToNative converts Value to a native go type.
// This does not work for sqltypes.Tuple. The function
// panics if there are inconsistencies.
func (v Value) ToNative() interface{} {
	var out interface{}
	var err error
	switch {
	case v.typ == Null:
		// no-op
	case IsSigned(v.typ):
		out, err = v.ParseInt64()
	case IsUnsigned(v.typ):
		out, err = v.ParseUint64()
	case IsFloat(v.typ):
		out, err = v.ParseFloat64()
	case v.typ == Tuple:
		err = errors.New("unexpected tuple")
	default:
		out = v.val
	}
	if err != nil {
		panic(err)
	}
	return out
}

// ToProtoValue converts Value to a querypb.Value.
func (v Value) ToProtoValue() *querypb.Value {
	return &querypb.Value{
		Type:  v.typ,
		Value: v.val,
	}
}

// ParseInt64 will parse a Value into an int64. It does
// not check the type.
func (v Value) ParseInt64() (val int64, err error) {
	return strconv.ParseInt(v.String(), 10, 64)
}

// ParseUint64 will parse a Value into a uint64. It does
// not check the type.
func (v Value) ParseUint64() (val uint64, err error) {
	return strconv.ParseUint(v.String(), 10, 64)
}

// ParseFloat64 will parse a Value into an float64. It does
// not check the type.
func (v Value) ParseFloat64() (val float64, err error) {
	return strconv.ParseFloat(v.String(), 64)
}

// EncodeSQL encodes the value into an SQL statement. Can be binary.
func (v Value) EncodeSQL(b BinWriter) {
	// ToNative panics if v is invalid.
	_ = v.ToNative()
	switch {
	case v.typ == Null:
		writebytes(nullstr, b)
	case IsQuoted(v.typ):
		encodeBytesSQL(v.val, b)
	default:
		writebytes(v.val, b)
	}
}

// EncodeASCII encodes the value using 7-bit clean ascii bytes.
func (v Value) EncodeASCII(b BinWriter) {
	// ToNative panics if v is invalid.
	_ = v.ToNative()
	switch {
	case v.typ == Null:
		writebytes(nullstr, b)
	case IsQuoted(v.typ):
		encodeBytesASCII(v.val, b)
	default:
		writebytes(v.val, b)
	}
}

// IsNull returns true if Value is null.
func (v Value) IsNull() bool {
	return v.typ == Null
}

// IsIntegral returns true if Value is an integral.
func (v Value) IsIntegral() bool {
	return IsIntegral(v.typ)
}

// IsSigned returns true if Value is a signed integral.
func (v Value) IsSigned() bool {
	return IsSigned(v.typ)
}

// IsUnsigned returns true if Value is an unsigned integral.
func (v Value) IsUnsigned() bool {
	return IsUnsigned(v.typ)
}

// IsFloat returns true if Value is a float.
func (v Value) IsFloat() bool {
	return IsFloat(v.typ)
}

// IsQuoted returns true if Value must be SQL-quoted.
func (v Value) IsQuoted() bool {
	return IsQuoted(v.typ)
}

// IsText returns true if Value is a collatable text.
func (v Value) IsText() bool {
	return IsText(v.typ)
}

// IsBinary returns true if Value is binary.
func (v Value) IsBinary() bool {
	return IsBinary(v.typ)
}

// MarshalJSON should only be used for testing.
// It's not a complete implementation.
func (v Value) MarshalJSON() ([]byte, error) {
	switch {
	case v.IsQuoted():
		return json.Marshal(v.String())
	case v.typ == Null:
		return nullstr, nil
	}
	return v.val, nil
}

// UnmarshalJSON should only be used for testing.
// It's not a complete implementation.
func (v *Value) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("error unmarshaling empty bytes")
	}
	var val interface{}
	var err error
	switch b[0] {
	case '-':
		var ival int64
		err = json.Unmarshal(b, &ival)
		val = ival
	case '"':
		var bval []byte
		err = json.Unmarshal(b, &bval)
		val = bval
	case 'n': // null
		err = json.Unmarshal(b, &val)
	default:
		var uval uint64
		err = json.Unmarshal(b, &uval)
		val = uval
	}
	if err != nil {
		return err
	}
	*v, err = BuildValue(val)
	return err
}

func encodeBytesSQL(val []byte, b BinWriter) {
	writebyte('\'', b)
	for _, ch := range val {
		if encodedChar := SQLEncodeMap[ch]; encodedChar == DontEscape {
			writebyte(ch, b)
		} else {
			writebyte('\\', b)
			writebyte(encodedChar, b)
		}
	}
	writebyte('\'', b)
}

func encodeBytesASCII(val []byte, b BinWriter) {
	writebyte('\'', b)
	encoder := base64.NewEncoder(base64.StdEncoding, b)
	encoder.Write(val)
	encoder.Close()
	writebyte('\'', b)
}

func writebyte(c byte, b BinWriter) {
	if err := b.WriteByte(c); err != nil {
		panic(err)
	}
}

func writebytes(val []byte, b BinWriter) {
	n, err := b.Write(val)
	if err != nil {
		panic(err)
	}
	if n != len(val) {
		panic(errors.New("short write"))
	}
}

// SQLEncodeMap specifies how to escape binary data with '\'.
// Complies to http://dev.mysql.com/doc/refman/5.1/en/string-syntax.html
var SQLEncodeMap [256]byte

// SQLDecodeMap is the reverse of SQLEncodeMap
var SQLDecodeMap [256]byte

var encodeRef = map[byte]byte{
	'\x00': '0',
	'\'':   '\'',
	'"':    '"',
	'\b':   'b',
	'\n':   'n',
	'\r':   'r',
	'\t':   't',
	26:     'Z', // ctl-Z
	'\\':   '\\',
}

func init() {
	for i := range SQLEncodeMap {
		SQLEncodeMap[i] = DontEscape
		SQLDecodeMap[i] = DontEscape
	}
	for i := range SQLEncodeMap {
		if to, ok := encodeRef[byte(i)]; ok {
			SQLEncodeMap[byte(i)] = to
			SQLDecodeMap[to] = byte(i)
		}
	}
}
