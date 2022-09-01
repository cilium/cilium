// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

//
// In this file, we define types and utilities for cluster-aware
// addressing which identifies network endpoints using IP address
// and an optional ClusterID. With this special addressing scheme,
// we can distinguish network endpoints (e.g. Pods) that have the
// same IP address, but belong to the different cluster.
//
// A "bare" IP address is still a valid identifier because there
// are cases that endpoints can be identified without ClusterID
// (e.g. network endpoint has a unique IP address). We can consider
// this as a special case that ClusterID "doesn't matter". ClusterID
// 0 is reserved for indicating that.
//

// AddrCluster is a type that holds a pair of IP and ClusterID.
// We should use this type as much as possible when we implement
// IP + Cluster addressing. We should avoid managing IP and ClusterID
// separately. Otherwise, it is very hard for code readers to see
// where we are using cluster-aware addressing.
type AddrCluster struct {
	addr      netip.Addr
	clusterID uint32
}

// ParseAddrCluster parses s as an IP + ClusterID and returns AddrCluster.
// The string s can be a bare IP string (any IP address format allowed in
// netip.ParseAddr()) or IP string + @ + ClusterID with decimal. Bare IP
// string is considered as IP string + @ + ClusterID = 0.
func ParseAddrCluster(s string) (AddrCluster, error) {
	atIndex := strings.LastIndex(s, "@")

	var (
		addrStr      string
		clusterIDStr string
	)

	if atIndex == -1 {
		// s may be a bare IP address string, still valid
		addrStr = s
		clusterIDStr = ""
	} else {
		// s may be a IP + ClusterID string
		addrStr = s[:atIndex]
		clusterIDStr = s[atIndex+1:]
	}

	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return AddrCluster{}, err
	}

	if clusterIDStr == "" {
		if atIndex != len(s)-1 {
			return AddrCluster{addr: addr, clusterID: 0}, nil
		} else {
			// handle the invalid case like "10.0.0.0@"
			return AddrCluster{}, fmt.Errorf("empty cluster ID")
		}
	}

	clusterID64, err := strconv.ParseUint(clusterIDStr, 10, 32)
	if err != nil {
		return AddrCluster{}, err
	}

	return AddrCluster{addr: addr, clusterID: uint32(clusterID64)}, nil
}

// MustParseAddrCluster calls ParseAddr(s) and panics on error. It is
// intended for use in tests with hard-coded strings.
func MustParseAddrCluster(s string) AddrCluster {
	addrCluster, err := ParseAddrCluster(s)
	if err != nil {
		panic(err)
	}
	return addrCluster
}

// Addr returns IP address part of AddrCluster as netip.Addr. This function
// exists for keeping backward compatibility between the existing components
// which are not aware of the cluster-aware addressing. Calling this function
// against the AddrCluster which has non-zero clusterID will lose the ClusterID
// information. It should be used with an extra care.
func (ac AddrCluster) Addr() netip.Addr {
	return ac.addr
}
