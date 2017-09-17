package _generated

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/tinylib/msgp/msgp"
)

func TestRuneEncodeDecode(t *testing.T) {
	tt := &TestType{}
	r := 'r'
	rp := &r
	tt.Rune = r
	tt.RunePtr = &r
	tt.RunePtrPtr = &rp
	tt.RuneSlice = []rune{'a', 'b', '😳'}

	var buf bytes.Buffer
	wrt := msgp.NewWriter(&buf)
	if err := tt.EncodeMsg(wrt); err != nil {
		t.Errorf("%v", err)
	}
	wrt.Flush()

	var out TestType
	rdr := msgp.NewReader(&buf)
	if err := (&out).DecodeMsg(rdr); err != nil {
		t.Errorf("%v", err)
	}
	if r != out.Rune {
		t.Errorf("rune mismatch: expected %c found %c", r, out.Rune)
	}
	if r != *out.RunePtr {
		t.Errorf("rune ptr mismatch: expected %c found %c", r, *out.RunePtr)
	}
	if r != **out.RunePtrPtr {
		t.Errorf("rune ptr ptr mismatch: expected %c found %c", r, **out.RunePtrPtr)
	}
	if !reflect.DeepEqual(tt.RuneSlice, out.RuneSlice) {
		t.Errorf("rune slice mismatch")
	}
}

func TestRuneMarshalUnmarshal(t *testing.T) {
	tt := &TestType{}
	r := 'r'
	rp := &r
	tt.Rune = r
	tt.RunePtr = &r
	tt.RunePtrPtr = &rp
	tt.RuneSlice = []rune{'a', 'b', '😳'}

	bts, err := tt.MarshalMsg(nil)
	if err != nil {
		t.Errorf("%v", err)
	}

	var out TestType
	if _, err := (&out).UnmarshalMsg(bts); err != nil {
		t.Errorf("%v", err)
	}
	if r != out.Rune {
		t.Errorf("rune mismatch: expected %c found %c", r, out.Rune)
	}
	if r != *out.RunePtr {
		t.Errorf("rune ptr mismatch: expected %c found %c", r, *out.RunePtr)
	}
	if r != **out.RunePtrPtr {
		t.Errorf("rune ptr ptr mismatch: expected %c found %c", r, **out.RunePtrPtr)
	}
	if !reflect.DeepEqual(tt.RuneSlice, out.RuneSlice) {
		t.Errorf("rune slice mismatch")
	}
}
