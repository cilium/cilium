// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package cgroups

import "errors"

var ErrNotImplemented = errors.New("not implemented")

func mountCgroup() error {
	return ErrNotImplemented
}

func cgrpCheckOrMountLocation(cgroupRoot string) error {
	return ErrNotImplemented
}

func GetCgroupID(cgroupPath string) (uint64, error) {
	return 0, ErrNotImplemented
}
