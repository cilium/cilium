// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

// +build !linux

package cgroups

import "errors"

var ErrNotImplemented = errors.New("not implemented")

func mountCgroup() error {
	return ErrNotImplemented
}

func cgrpCheckOrMountLocation(cgroupRoot string) error {
	return ErrNotImplemented
}
