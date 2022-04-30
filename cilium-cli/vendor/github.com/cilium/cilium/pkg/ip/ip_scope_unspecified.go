// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package ip

import (
	"errors"
)

var ErrNotImplemented = errors.New("not implemented")

func ParseScope(scope string) (int, error) {
	return 0, ErrNotImplemented
}
