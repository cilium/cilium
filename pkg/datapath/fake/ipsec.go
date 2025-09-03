// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"github.com/cilium/cilium/pkg/datapath/types"
)

type ipsecAgent struct{}

func (*ipsecAgent) AuthKeySize() int {
	return 16
}

func (*ipsecAgent) SPI() uint8 {
	return 4
}

func (*ipsecAgent) StartBackgroundJobs(types.NodeHandler) error {
	return nil
}

var _ types.IPsecAgent = &ipsecAgent{}
