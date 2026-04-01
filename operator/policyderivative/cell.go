// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policyderivative

import (
	"github.com/cilium/hive/cell"
)

// Cell is a cell that implements watchers for CiliumNetworkPolicy and
// CiliumClusterwideNetworkPolicy derivative policies. These watchers monitor
// policy CRD events and manage derivative policies for network policy groups.
var Cell = cell.Module(
	"policy-derivative",
	"CNP and CCNP derivative policy watcher",

	cell.Invoke(registerWatchers),
)

// SharedConfig contains the configuration that is shared between this module and others.
type SharedConfig struct {
	// EnableCiliumNetworkPolicy indicates whether CNP support is enabled
	EnableCiliumNetworkPolicy bool

	// EnableCiliumClusterwideNetworkPolicy indicates whether CCNP support is enabled
	EnableCiliumClusterwideNetworkPolicy bool

	// ClusterName is the name of the cluster
	ClusterName string

	// K8sEnabled indicates whether Kubernetes support is enabled
	K8sEnabled bool
}
