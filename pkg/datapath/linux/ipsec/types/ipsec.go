// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"

	"github.com/cilium/cilium/pkg/node"
)

type Config interface {
	Enabled() bool
	UseCiliumInternalIP() bool
	DNSProxyInsecureSkipTransparentModeCheckEnabled() bool
}

type Agent interface {
	Enabled() bool
	AuthKeySize() int
	SPI() uint8
	StartBackgroundJobs(node.Handler) error
	UpsertIPsecEndpoint(params *Parameters) (uint8, error)
	DeleteIPsecEndpoint(nodeID uint16) error
	DeleteXFRM(reqID int) error
	DeleteXfrmPolicyOut(nodeID uint16, dst *net.IPNet) error
}
