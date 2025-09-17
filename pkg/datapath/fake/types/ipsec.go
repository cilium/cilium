// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net"

	"github.com/cilium/cilium/pkg/datapath/types"
)

var (
	_ types.IPsecAgent  = &IPsecAgent{}
	_ types.IPsecConfig = &IPsecConfig{}
)

type IPsecAgent struct {
	EnableIPsec bool
}

func (*IPsecAgent) AuthKeySize() int {
	return 16
}

func (*IPsecAgent) SPI() uint8 {
	return 4
}

func (*IPsecAgent) StartBackgroundJobs(types.NodeHandler) error {
	return nil
}

func (a *IPsecAgent) UpsertIPsecEndpoint(params *types.IPSecParameters) (uint8, error) {
	return 0, nil
}

func (a *IPsecAgent) DeleteIPsecEndpoint(nodeID uint16) error {
	return nil
}

func (a *IPsecAgent) DeleteXFRM(reqID int) error {
	return nil
}

func (a *IPsecAgent) DeleteXfrmPolicyOut(nodeID uint16, dst *net.IPNet) error {
	return nil
}

func (a *IPsecAgent) Enabled() bool {
	return a.EnableIPsec
}

type IPsecConfig struct {
	EnableIPsec                              bool
	EncryptedOverlay                         bool
	UseCiliumInternalIPForIPsec              bool
	DNSProxyInsecureSkipTransparentModeCheck bool
}

func (c IPsecConfig) Enabled() bool {
	return c.EnableIPsec
}

func (c IPsecConfig) UseCiliumInternalIP() bool {
	return c.UseCiliumInternalIPForIPsec
}

func (c IPsecConfig) DNSProxyInsecureSkipTransparentModeCheckEnabled() bool {
	return c.DNSProxyInsecureSkipTransparentModeCheck
}
