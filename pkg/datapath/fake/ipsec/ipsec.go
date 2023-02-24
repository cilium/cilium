// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import (
	"net"

	real_ipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec"
)

type IPSecManager struct{}

func (im *IPSecManager) GetAuthKeySize() int {
	return 0
}

func (im *IPSecManager) GetCurrentKeySPI() uint8 {
	return 0
}

func (im *IPSecManager) IpSecReplacePolicyFwd(dst *net.IPNet, tmplDst net.IP) error {
	return nil
}

func (im *IPSecManager) UpsertIPsecEndpoint(local *net.IPNet, remote *net.IPNet, outerLocal net.IP, outerRemote net.IP, dir real_ipsec.IPSecDir, outputMark bool) (uint8, error) {
	return 0, nil
}

func (im *IPSecManager) UpsertIPsecEndpointPolicy(local *net.IPNet, remote *net.IPNet, localTmpl net.IP, remoteTmpl net.IP, dir real_ipsec.IPSecDir) error {
	return nil
}
