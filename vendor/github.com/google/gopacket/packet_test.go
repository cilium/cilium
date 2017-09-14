// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package gopacket

import (
	"reflect"
	"testing"
)

type embedded struct {
	A, B int
}

type embedding struct {
	embedded
	C, D int
}

func TestDumpEmbedded(t *testing.T) {
	e := embedding{embedded: embedded{A: 1, B: 2}, C: 3, D: 4}
	if got, want := layerString(reflect.ValueOf(e), false, false), "{A=1 B=2 C=3 D=4}"; got != want {
		t.Errorf("embedded dump mismatch:\n   got: %v\n  want: %v", got, want)
	}
}
