// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package serializer

import (
	"errors"
	"testing"
)

func TestFuncSerializer(t *testing.T) {
	terr := errors.New("Failed")

	f := func() error {
		return terr
	}

	fs := NewFunctionQueue()
	fs.Enqueue(f)

	if err := fs.Wait(); err != terr {
		t.Errorf("Expected error %s, got: %s", terr, err)
	}
}
