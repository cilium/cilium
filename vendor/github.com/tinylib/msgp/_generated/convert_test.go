package _generated

import (
	"bytes"
	"testing"

	"github.com/tinylib/msgp/msgp"
)

func TestConvertFromEncodeError(t *testing.T) {
	e := ConvertErr{ConvertErrVal(fromFailStr)}
	var buf bytes.Buffer
	w := msgp.NewWriter(&buf)
	err := e.EncodeMsg(w)
	if err != errConvertFrom {
		t.Fatalf("expected conversion error, found %v", err.Error())
	}
}

func TestConvertToEncodeError(t *testing.T) {
	var in, out ConvertErr
	in = ConvertErr{ConvertErrVal(toFailStr)}
	var buf bytes.Buffer
	w := msgp.NewWriter(&buf)
	err := in.EncodeMsg(w)
	if err != nil {
		t.FailNow()
	}
	w.Flush()

	r := msgp.NewReader(&buf)
	err = (&out).DecodeMsg(r)
	if err != errConvertTo {
		t.Fatalf("expected conversion error, found %v", err.Error())
	}
}

func TestConvertFromMarshalError(t *testing.T) {
	e := ConvertErr{ConvertErrVal(fromFailStr)}
	var b []byte
	_, err := e.MarshalMsg(b)
	if err != errConvertFrom {
		t.Fatalf("expected conversion error, found %v", err.Error())
	}
}

func TestConvertToMarshalError(t *testing.T) {
	var in, out ConvertErr
	in = ConvertErr{ConvertErrVal(toFailStr)}
	b, err := in.MarshalMsg(nil)
	if err != nil {
		t.FailNow()
	}

	_, err = (&out).UnmarshalMsg(b)
	if err != errConvertTo {
		t.Fatalf("expected conversion error, found %v", err.Error())
	}
}
