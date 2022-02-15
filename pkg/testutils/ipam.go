// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// FakeAcknowledgeReleaseIps Fake acknowledge IPs marked for release like cilium agent would.
func FakeAcknowledgeReleaseIps(cn *v2.CiliumNode) {
	for ip, status := range cn.Status.IPAM.ReleaseIPs {
		if status == ipamOption.IPAMMarkForRelease {
			cn.Status.IPAM.ReleaseIPs[ip] = ipamOption.IPAMReadyForRelease
		}
	}
}
