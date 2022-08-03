// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

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

// NewIPCluster creates a new IPCluster object and initialize it with
// given ip and clusterID.
func NewIPCluster(ip string, clusterID uint32) IPCluster {
	return IPCluster{
		ip:        ip,
		clusterID: clusterID,
	}
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
