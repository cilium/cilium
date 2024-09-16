// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package awscni

import (
	"net"
	"strings"

	cniTypesVer "github.com/containernetworking/cni/pkg/types/100"
)

// awsCNIInterfacePrefixSGPP the prefix used by the AWS CNI to build the
// name of the host side interface for security group attached Pods
const awsCNIIfacePrefixSGPPod = "vlan"

// isSGPPodAttachment returns true if this is an attachment for a
// security group attached Pod following strict enforcement
func isSGPPodAttachment(res *cniTypesVer.Result) bool {
	return strings.HasPrefix(getHostIface(res), awsCNIIfacePrefixSGPPod)
}

// awsCNIIPIndexHost is the index into the result IPConfig array of the
// of the new Pod's IP Address
const awsCNIIPIndexHost = iota

// getSGPPodAddr returns the IP of the security group attached Pod from
// the AWS CNI Result
func getSGPPodAddr(res *cniTypesVer.Result) net.IPNet {
	return res.IPs[awsCNIIPIndexHost].Address
}

const (
	// awsCNIIfaceIndexHost is the index into the result interfaces
	// array of the new Pod's host side veth interface
	awsCNIIfaceIndexHost = iota
	_
	// awsCNIIfaceIndexDummy is the index into the result interfaces
	// array of the AWS CNI dummy interface
	awsCNIIfaceIndexDummy
)

func getHostIface(res *cniTypesVer.Result) string {
	return res.Interfaces[awsCNIIfaceIndexHost].Name
}

// getSGPPodVLANID returns the VLAN ID associated with the security
// group attached Pod from the AWS CNI Result
func getSGPPodVLANID(res *cniTypesVer.Result) string {
	return res.Interfaces[awsCNIIfaceIndexDummy].Mac
}
