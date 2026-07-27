// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"net"

	ipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	"github.com/cilium/cilium/pkg/node"
)

var (
	_ ipsec.Agent  = &Agent{}
	_ ipsec.Config = &Config{}
)

type Agent struct {
	EnableIPsec bool
}

func (*Agent) AuthKeySize() int {
	return 16
}

func (*Agent) StartBackgroundJobs(node.Handler, <-chan struct{}) error {
	return nil
}

func (a *Agent) UpsertIPsecEndpoint(params *ipsec.Parameters) (uint8, error) {
	return 0, nil
}

func (a *Agent) DeleteIPsecEndpoint(nodeID uint16) error {
	return nil
}

func (a *Agent) DeleteXFRM(reqID int) error {
	return nil
}

func (a *Agent) DeleteXfrmPolicyOut(nodeID uint16, dst *net.IPNet) error {
	return nil
}

func (a *Agent) Enabled() bool {
	return a.EnableIPsec
}

type Config struct {
	EnableIPsec                              bool
	UseCiliumInternalIPForIPsec              bool
	DNSProxyInsecureSkipTransparentModeCheck bool
}

func (c Config) Enabled() bool {
	return c.EnableIPsec
}

func (c Config) UseCiliumInternalIP() bool {
	return c.UseCiliumInternalIPForIPsec
}

func (c Config) DNSProxyInsecureSkipTransparentModeCheckEnabled() bool {
	return c.DNSProxyInsecureSkipTransparentModeCheck
}
