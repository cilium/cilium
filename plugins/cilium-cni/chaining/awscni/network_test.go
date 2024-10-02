// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package awscni

import (
	"fmt"
	"net"
	"testing"

	cniTypesVer "github.com/containernetworking/cni/pkg/types/100"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

const (
	mockHostIfName = "vlandeadbeef"

	mockPodIfName = "eth0"
	mockPodVLANID = 9
)

var (
	mockPodIP = net.IPv4(10, 10, 10, 33)

	mockAWSCNIResult = cniTypesVer.Result{
		Interfaces: []*cniTypesVer.Interface{
			{
				Name: mockHostIfName,
			}, {
				Name: mockPodIfName,
			},
			{
				Name: "dummy",
				Mac:  fmt.Sprintf("%d", mockPodVLANID),
			},
		},
		IPs: []*cniTypesVer.IPConfig{
			{
				Interface: cniTypesVer.Int(0),
				Address: net.IPNet{
					IP:   mockPodIP,
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
			},
		},
	}
)

func TestInstallSGPPRules(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		awsCNIRes := awsCNIResult(mockAWSCNIResult)

		podHostIface, ok := awsCNIRes.getSGPPHostIface()
		assert.True(t, ok)
		assert.Equal(t, mockHostIfName, podHostIface)

		podVLANID, ok := awsCNIRes.getSGPPVLANID()
		assert.True(t, ok)
		assert.Equal(t, podVLANID, fmt.Sprintf("%d", mockPodVLANID))

		PodAddr, ok := awsCNIRes.getSGPPAddr()
		assert.True(t, ok)
		assert.Equal(t, net.IPv4(10, 10, 10, 33), PodAddr.IP)

		err := installSGPPProxyRules(podVLANID, PodAddr)
		assert.NoError(t, err)

		rules, err := route.ListRules(netlink.FAMILY_V4, &route.Rule{
			Table: 100 + mockPodVLANID,
		})
		assert.NoError(t, err)
		assert.Len(t, rules, 2)

		ruleOriginProxyToPod := rules[0]
		assert.Equal(t, 100+mockPodVLANID, ruleOriginProxyToPod.Table)
		assert.Equal(t, mockPodIP.To4(), ruleOriginProxyToPod.Dst.IP)

		ruleTerminateProxyFromPod := rules[1]
		assert.Equal(t, 100+mockPodVLANID, ruleTerminateProxyFromPod.Table)
		assert.Equal(t, mockPodIP.To4(), ruleTerminateProxyFromPod.Src.IP)

		return nil
	})
}
