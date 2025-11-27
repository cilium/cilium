// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import "errors"

var (
	errAllocationAlreadyExistsForPod = errors.New("allocation already exists for pod")
	errUnexpectedInput               = errors.New("unexpected input")
	errDeviceNotFound                = errors.New("device not found")

	errBadConfig              = errors.New("bad config")
	errDuplicatedPoolName     = errors.New("duplicated pool name")
	errIfNameInMultiplePools  = errors.New("ifname contained in multiple pools")
	errPCIAddrInMultiplePools = errors.New("pci addr contained in multiple pools")
)
