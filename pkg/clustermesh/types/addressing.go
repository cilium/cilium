// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"
	"net"
	"strconv"
)

//
// In this file, we define types and utilities for cluster-aware
// addressing which identifies network endpoints using IP address
// and an optional ClusterID. With this special addressing scheme,
// we can distinguish network endpoints (e.g. Pods) that have the
// same IP address, but belong to the different cluster.
//
// A "plain" IP address is still a valid identifier because there
// are cases that endpoints can be identified without ClusterID
// (e.g. network endpoint has a unique IP address). We can consider
// this as a special case that ClusterID "doesn't matter". ClusterID
// 0 is reserved for indicating that.
//

// IPCluster is a type that holds a set of IP string and ClusterID.
// We must always use this type when we possibly use IP + Cluster
// addressing. We should avoid managing IP and ClusterID separately.
// Otherwise, it is very hard for code readers to see where we are
// using cluster-aware addressing.
type IPCluster struct {
	ip        string
	clusterID uint32
}

// IPClusterBytesLen is a length of the binary representation of
// IPCluster. IP with 16bytes representation + 4bytes ClusterID = 20.
const IPClusterBytesLen = 20

// NewIPCluster creates a new IPCluster object and initialize it with
// given ip and clusterID.
func NewIPCluster(ip string, clusterID uint32) IPCluster {
	return IPCluster{
		ip:        ip,
		clusterID: clusterID,
	}
}

// String returns string representation of the IPCluster with one of
// following two formats.
//
// - IP address format: 10.0.0.1, a::1
// - IP address @ ClusterID format: 10.0.0.1@1, a::1@1
//
// Note that when ClusterID is zero (doesn't matter), ClusterID must
// be omitted (the string must be plain IP address). This function
// should be used only for printing / logging purpose.
func (ipc IPCluster) String() string {
	if ipc.clusterID == 0 {
		return ipc.ip
	}
	clusterIDStr := strconv.FormatUint(uint64(ipc.clusterID), 10)
	return ipc.ip + "@" + clusterIDStr
}

// IPString returns IP address string part of IPCluster. This function
// exists for keeping backward compatibility between the existing
// components which are not aware of the cluster-aware addressing.
// Calling this function against the IPCluster which has non-zero
// clusterID will lose the clusterID information. It should be used
// with an extra care.
func (ipc IPCluster) IPString() string {
	return ipc.ip
}

// ClusterID returns ClusterID part of the IPCluster. This function
// exists for the cases that we need to separate IP and ClusterID to
// avoid breaking user interface. Don't use this function for other
// purposes. Treating IP and ClusterID separately should be avoided
// as much as possible.
func (ipc IPCluster) ClusterID() uint32 {
	return ipc.clusterID
}

// Bytes returns a binary representation of the IPCluster. It is a
// simple format that just concatenates 16bytes representation of
// IP and 4bytes ClusterID.
func (ipc IPCluster) Bytes() []byte {
	ret := make([]byte, IPClusterBytesLen)
	ip := net.ParseIP(ipc.ip)
	copy(ret, ip.To16())
	for i := 0; i < 4; i++ {
		ret[net.IPv6len+i] = byte((ipc.clusterID >> (8 * i)) & 0xff)
	}
	return ret
}

// IsIPv4 returns whether the IP part of the IPCluster is an IPv4
// address or not.
func (ipc IPCluster) IsIPv4() bool {
	return net.ParseIP(ipc.ip).To4() != nil
}

// IsIPv6 returns whether the IP part of the IPCluster is an IPv6
// address or not.
func (ipc IPCluster) IsIPv6() bool {
	return net.ParseIP(ipc.ip).To4() == nil
}

// Equal retuns if given IPCluster equals to itself
func (ipc0 IPCluster) Equal(ipc1 IPCluster) bool {
	return ipc0.ip == ipc1.ip && ipc0.clusterID == ipc1.clusterID
}

// JoinIPClusterPort combines IPCluster and Port number into an
// IP + Port + Cluster form which has following possible format.
// - IP:Port format (when ClusterID = 0): 10.0.0.1:80, [a::1]:80
// - IP:Port@ClusterID format: 10.0.0.1:80@1, [a::1]:80@1
func JoinIPClusterPort(ipCluster IPCluster, port uint16) string {
	var ipStr string

	ip := net.ParseIP(ipCluster.ip)
	if ip.To4() == nil {
		ipStr = "[" + ip.String() + "]"
	} else {
		ipStr = ip.String()
	}

	if ipCluster.clusterID == 0 {
		return fmt.Sprintf("%s:%d", ipStr, port)
	} else {
		return fmt.Sprintf("%s:%d@%d", ipStr, port, ipCluster.clusterID)
	}
}
