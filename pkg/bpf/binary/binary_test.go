// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2009 The Go Authors. All rights reserved.
// This file was borrowed from Go's src/encoding/binary/binary_test.go.

package binary

import (
	"encoding/binary"
	"math"
	"reflect"
	"testing"
)

type Struct struct {
	Int8       int8
	Int16      int16
	Int32      int32
	Int64      int64
	Uint8      uint8
	Uint16     uint16
	Uint32     uint32
	Uint64     uint64
	Float32    float32
	Float64    float64
	Complex64  complex64
	Complex128 complex128
	Array      [4]uint8
	Bool       bool
	BoolArray  [4]bool
}

var s = Struct{
	0x01,
	0x0203,
	0x04050607,
	0x08090a0b0c0d0e0f,
	0x10,
	0x1112,
	0x13141516,
	0x1718191a1b1c1d1e,

	math.Float32frombits(0x1f202122),
	math.Float64frombits(0x232425262728292a),
	complex(
		math.Float32frombits(0x2b2c2d2e),
		math.Float32frombits(0x2f303132),
	),
	complex(
		math.Float64frombits(0x333435363738393a),
		math.Float64frombits(0x3b3c3d3e3f404142),
	),

	[4]uint8{0x43, 0x44, 0x45, 0x46},

	true,
	[4]bool{true, false, true, false},
}

var big = []byte{
	1,
	2, 3,
	4, 5, 6, 7,
	8, 9, 10, 11, 12, 13, 14, 15,
	16,
	17, 18,
	19, 20, 21, 22,
	23, 24, 25, 26, 27, 28, 29, 30,

	31, 32, 33, 34,
	35, 36, 37, 38, 39, 40, 41, 42,
	43, 44, 45, 46, 47, 48, 49, 50,
	51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66,

	67, 68, 69, 70,

	1,
	1, 0, 1, 0,
}

var little = []byte{
	1,
	3, 2,
	7, 6, 5, 4,
	15, 14, 13, 12, 11, 10, 9, 8,
	16,
	18, 17,
	22, 21, 20, 19,
	30, 29, 28, 27, 26, 25, 24, 23,

	34, 33, 32, 31,
	42, 41, 40, 39, 38, 37, 36, 35,
	46, 45, 44, 43, 50, 49, 48, 47,
	58, 57, 56, 55, 54, 53, 52, 51, 66, 65, 64, 63, 62, 61, 60, 59,

	67, 68, 69, 70,

	1,
	1, 0, 1, 0,
}

var src = []byte{1, 2, 3, 4, 5, 6, 7, 8}
var res = []int32{0x01020304, 0x05060708}

func checkResult(t *testing.T, dir string, order binary.ByteOrder, err error, have, want interface{}) {
	if err != nil {
		t.Errorf("%v %v: %v", dir, order, err)
		return
	}
	if !reflect.DeepEqual(have, want) {
		t.Errorf("%v %v:\n\thave %+v\n\twant %+v", dir, order, have, want)
	}
}

func testRead(t *testing.T, order binary.ByteOrder, b []byte, s1 interface{}) {
	var s2 Struct
	err := Read(b, order, &s2)
	checkResult(t, "Read", order, err, s2, s1)
}

func TestLittleEndianRead(t *testing.T) { testRead(t, binary.LittleEndian, little, s) }

func TestBigEndianRead(t *testing.T) { testRead(t, binary.BigEndian, big, s) }

func TestReadSlice(t *testing.T) {
	slice := make([]int32, 2)
	err := Read(src, binary.BigEndian, slice)
	checkResult(t, "ReadSlice", binary.BigEndian, err, slice, res)
}

func TestReadBool(t *testing.T) {
	var res bool
	var err error
	err = Read([]byte{0}, binary.BigEndian, &res)
	checkResult(t, "ReadBool", binary.BigEndian, err, res, false)
	res = false
	err = Read([]byte{1}, binary.BigEndian, &res)
	checkResult(t, "ReadBool", binary.BigEndian, err, res, true)
	res = false
	err = Read([]byte{2}, binary.BigEndian, &res)
	checkResult(t, "ReadBool", binary.BigEndian, err, res, true)
}

func TestReadBoolSlice(t *testing.T) {
	slice := make([]bool, 4)
	err := Read([]byte{0, 1, 2, 255}, binary.BigEndian, slice)
	checkResult(t, "ReadBoolSlice", binary.BigEndian, err, slice, []bool{false, true, true, true})
}
