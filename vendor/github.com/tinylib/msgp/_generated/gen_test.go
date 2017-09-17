package _generated

import (
	"bytes"
	"github.com/tinylib/msgp/msgp"
	"reflect"
	"testing"
	"time"
)

// benchmark encoding a small, "fast" type.
// the point here is to see how much garbage
// is generated intrinsically by the encoding/
// decoding process as opposed to the nature
// of the struct.
func BenchmarkFastEncode(b *testing.B) {
	v := &TestFast{
		Lat:  40.12398,
		Long: -41.9082,
		Alt:  201.08290,
		Data: []byte("whaaaaargharbl"),
	}
	var buf bytes.Buffer
	msgp.Encode(&buf, v)
	en := msgp.NewWriter(msgp.Nowhere)
	b.SetBytes(int64(buf.Len()))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.EncodeMsg(en)
	}
	en.Flush()
}

// benchmark decoding a small, "fast" type.
// the point here is to see how much garbage
// is generated intrinsically by the encoding/
// decoding process as opposed to the nature
// of the struct.
func BenchmarkFastDecode(b *testing.B) {
	v := &TestFast{
		Lat:  40.12398,
		Long: -41.9082,
		Alt:  201.08290,
		Data: []byte("whaaaaargharbl"),
	}

	var buf bytes.Buffer
	msgp.Encode(&buf, v)
	dc := msgp.NewReader(msgp.NewEndlessReader(buf.Bytes(), b))
	b.SetBytes(int64(buf.Len()))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.DecodeMsg(dc)
	}
}

func (a *TestType) Equal(b *TestType) bool {
	// compare times, then zero out those
	// fields, perform a DeepEqual, and restore them
	ta, tb := a.Time, b.Time
	if !ta.Equal(tb) {
		return false
	}
	a.Time, b.Time = time.Time{}, time.Time{}
	ok := reflect.DeepEqual(a, b)
	a.Time, b.Time = ta, tb
	return ok
}

// This covers the following cases:
//  - Recursive types
//  - Non-builtin identifiers (and recursive types)
//  - time.Time
//  - map[string]string
//  - anonymous structs
//
func Test1EncodeDecode(t *testing.T) {
	f := 32.00
	tt := &TestType{
		F: &f,
		Els: map[string]string{
			"thing_one": "one",
			"thing_two": "two",
		},
		Obj: struct {
			ValueA string `msg:"value_a"`
			ValueB []byte `msg:"value_b"`
		}{
			ValueA: "here's the first inner value",
			ValueB: []byte("here's the second inner value"),
		},
		Child:    nil,
		Time:     time.Now(),
		Appended: msgp.Raw([]byte{0xc0}), // 'nil'
	}

	var buf bytes.Buffer

	err := msgp.Encode(&buf, tt)
	if err != nil {
		t.Fatal(err)
	}

	tnew := new(TestType)

	err = msgp.Decode(&buf, tnew)
	if err != nil {
		t.Error(err)
	}

	if !tt.Equal(tnew) {
		t.Logf("in: %v", tt)
		t.Logf("out: %v", tnew)
		t.Fatal("objects not equal")
	}

	tanother := new(TestType)

	buf.Reset()
	msgp.Encode(&buf, tt)

	var left []byte
	left, err = tanother.UnmarshalMsg(buf.Bytes())
	if err != nil {
		t.Error(err)
	}
	if len(left) > 0 {
		t.Errorf("%d bytes left", len(left))
	}

	if !tt.Equal(tanother) {
		t.Logf("in: %v", tt)
		t.Logf("out: %v", tanother)
		t.Fatal("objects not equal")
	}
}

func TestIssue168(t *testing.T) {
	buf := bytes.Buffer{}
	test := TestObj{}

	msgp.Encode(&buf, &TestObj{ID1: "1", ID2: "2"})
	msgp.Decode(&buf, &test)

	if test.ID1 != "1" || test.ID2 != "2" {
		t.Fatalf("got back %+v", test)
	}
}
