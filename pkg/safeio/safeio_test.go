// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package safeio

import (
	"errors"
	"strings"
	"testing"
)

func TestReadLimitExceeds(t *testing.T) {
	str := "this string is 28 bytes long"
	r := strings.NewReader(str)
	buf, err := ReadAllLimit(r, ByteSize(30))
	if err != nil {
		t.Fatalf("did not exepect error: %v", err)
	}
	if string(buf) != str {
		t.Fatalf("returned buffer %s did not match the expected value %s", string(buf), str)
	}
}

func TestReadLimitIsLess(t *testing.T) {
	limit := int64(27)
	str := "this string is 28 bytes long"
	r := strings.NewReader(str)
	buf, err := ReadAllLimit(r, ByteSize(limit))

	if !errors.Is(err, ErrLimitReached) {
		t.Fatalf("expected err, %v, got: %v", ErrLimitReached, err)
	}
	if string(buf) != str[:limit] {
		t.Fatalf("returned buffer %q did not match the expected value %q", string(buf), str[:limit])
	}
}

func TestReadLimitIsEqual(t *testing.T) {
	limit := int64(28)
	str := "this string is 28 bytes long"
	r := strings.NewReader(str)
	buf, err := ReadAllLimit(r, ByteSize(limit))
	if err != nil {
		t.Fatalf("did not exepect error: %v", err)
	}
	if string(buf) != str {
		t.Fatalf("returned buffer %s did not match the expected value %s", string(buf), str)
	}
}

func TestReadLimitExceedsLargeBuffer(t *testing.T) {
	limit := KB * 2
	str := strings.Repeat(" ", 1024)
	r := strings.NewReader(str)
	buf, err := ReadAllLimit(r, limit)
	if err != nil {
		t.Fatalf("did not exepect error: %v", err)
	}
	if string(buf) != str {
		t.Fatal("returned buffer did not match the expected value")
	}
}

func TestReadLimitIsLessLargeBuffer(t *testing.T) {
	limit := KB
	str := strings.Repeat(" ", 2048)
	r := strings.NewReader(str)
	buf, err := ReadAllLimit(r, limit)
	if !errors.Is(err, ErrLimitReached) {
		t.Fatalf("expected err, %v, got: %v", ErrLimitReached, err)
	}
	if string(buf) == str {
		t.Fatal("returned buffer did not match the expected value")
	}
}

func TestReadLimitIsEqualLargeBuffer(t *testing.T) {
	limit := KB
	str := strings.Repeat(" ", int(limit))
	r := strings.NewReader(str)
	buf, err := ReadAllLimit(r, limit)
	if err != nil {
		t.Fatalf("did not exepect error: %v", err)
	}
	if string(buf) != str {
		t.Fatal("returned buffer did not match the expected value")
	}
}
