// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"context"

	"github.com/cilium/cilium/pkg/datapath/types"
)

type ipsecKeyCustodian struct{}

// AuthKeySize implements types.IPsecKeyCustodian.
func (*ipsecKeyCustodian) AuthKeySize() int {
	return 256 // vaguely probable.
}

// SPI implements types.IPsecKeyCustodian.
func (*ipsecKeyCustodian) SPI() uint8 {
	return 4
}

// StartBackgroundJobs implements types.IPsecKeyCustodian.
func (*ipsecKeyCustodian) StartBackgroundJobs(context.Context, types.NodeUpdater, types.NodeHandler) error {
	return nil
}

var _ types.IPsecKeyCustodian = &ipsecKeyCustodian{}
