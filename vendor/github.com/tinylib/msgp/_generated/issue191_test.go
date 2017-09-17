package _generated

import (
	"testing"
)

// Issue #191: panic in unsafe.UnsafeString()

func TestIssue191(t *testing.T) {
	b := []byte{0x81, 0xa0, 0xa0}
	var i Issue191
	_, err := (&i).UnmarshalMsg(b)
	if err != nil {
		t.Error(err)
	}
}
