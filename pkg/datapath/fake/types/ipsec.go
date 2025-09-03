// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/cilium/cilium/pkg/datapath/types"
)

type IPsecAgent struct{}

func (*IPsecAgent) AuthKeySize() int {
	return 16
}

func (*IPsecAgent) SPI() uint8 {
	return 4
}

func (*IPsecAgent) StartBackgroundJobs(types.NodeHandler) error {
	return nil
}

var _ types.IPsecAgent = &IPsecAgent{}
