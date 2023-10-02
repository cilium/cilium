// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !windows

package metrics

import (
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
)

// Errno2Outcome converts a unix.Errno to LabelOutcome
func Errno2Outcome(errno unix.Errno) string {
	if errno != 0 {
		return LabelValueOutcomeFail
	}

	return LabelValueOutcomeSuccess
}

func enableIfIndexMetric() bool {
	// On kernels which do not provide ifindex via the FIB, Cilium needs
	// to store it in the CT map, with a field limit of max(uint16).
	// The EndpointMaxIfindex metric can be used to determine if that
	// limit is approaching. However, it should only be enabled by
	// default if we observe that the FIB is not providing the ifindex.
	return probes.HaveFibIfindex() != nil
}
