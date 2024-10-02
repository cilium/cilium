// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package awscni

import (
	"net"
	"strings"

	cniTypesVer "github.com/containernetworking/cni/pkg/types/100"
)

type awsCNIResult cniTypesVer.Result

func (r awsCNIResult) getHostIfaceIndex(prefix string) (index int, ok bool) {
	for i, iface := range r.Interfaces {
		if iface.Sandbox != "" {
			continue
		}
		if strings.HasPrefix(iface.Name, prefix) {
			index, ok = i, true
		}
	}
	return
}

// getSGPPAddr returns the IP of the security group attached pod
func (r awsCNIResult) getSGPPAddr() (address net.IPNet, ok bool) {
	i, ok := r.getHostIfaceIndex(awsCNIIfacePrefixSGPP)
	if !ok {
		return
	}
	for _, ip := range r.IPs {
		if *(ip.Interface) == i {
			address = ip.Address
		}
	}
	return
}

// getSGPPHostIface returns the name of the host side interface of the
// security group attached pod
func (r awsCNIResult) getSGPPHostIface() (name string, ok bool) {
	i, ok := r.getHostIfaceIndex(awsCNIIfacePrefixSGPP)
	if ok {
		name = r.Interfaces[i].Name
	}
	return
}

// getSGPPVLANID returns the VLAN ID associated with the security group
// attached pod
func (r awsCNIResult) getSGPPVLANID() (vlanID string, ok bool) {
	i, ok := r.getHostIfaceIndex(awsCNIIfacePrefixDummy)
	if ok {
		vlanID = r.Interfaces[i].Mac
	}
	return
}
