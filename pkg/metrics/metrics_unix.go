// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2021 Authors of Cilium

//go:build !windows
// +build !windows

package metrics

import "golang.org/x/sys/unix"

// Errno2Outcome converts a unix.Errno to LabelOutcome
func Errno2Outcome(errno unix.Errno) string {
	if errno != 0 {
		return LabelValueOutcomeFail
	}

	return LabelValueOutcomeSuccess
}
