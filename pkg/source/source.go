// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package source

import (
	"slices"

	"github.com/cilium/hive/cell"
)

// Source describes the source of a definition
type Source string

const (
	// Unspec is used when the source is unspecified
	Unspec Source = "unspec"

	// KubeAPIServer is the source used for state which represents the
	// kube-apiserver, such as the IPs associated with it. This is not to be
	// confused with the Kubernetes source.
	// KubeAPIServer state has the strongest ownership and can only be
	// overwritten by itself.
	KubeAPIServer Source = "kube-apiserver"

	// Local is the source used for state derived from local agent state.
	// Local state has the second strongest ownership, behind KubeAPIServer.
	Local Source = "local"

	// KVStore is the source used for state derived from a key value store.
	// State in the key value stored takes precedence over orchestration
	// system state such as Kubernetes.
	KVStore Source = "kvstore"

	// CustomResource is the source used for state derived from Kubernetes
	// custom resources
	CustomResource Source = "custom-resource"

	// Kubernetes is the source used for state derived from Kubernetes
	Kubernetes Source = "k8s"

	// ClusterMesh is the source used for state derived from remote clusters
	ClusterMesh Source = "clustermesh"

	// LocalAPI is the source used for state derived from the API served
	// locally on the node.
	LocalAPI Source = "api"

	// Generated is the source used for generated state which can be
	// overwritten by all other sources, except for restored (and unspec).
	Generated Source = "generated"

	// Restored is the source used for restored state from data left behind
	// by the previous agent instance. Can be overwritten by all other
	// sources (except for unspec).
	Restored Source = "restored"

	// Directory is the source used for watching and reading
	// cilium network policy files from specific directory.
	Directory Source = "directory"

	// Please remember to add your source to defaultSources below.
)

// Sources is a priority-sorted slice of sources.
type Sources []Source

// The ordering in defaultSources is critical and it should only be changed
// with care because as it determines the behavior of AllowOverwrite().
// It is from highest precedence to lowest precedence.
var defaultSources Sources = []Source{
	KubeAPIServer,
	Local,
	KVStore,
	CustomResource,
	Kubernetes,
	ClusterMesh,
	Directory,
	LocalAPI,
	Generated,
	Restored,
	Unspec,
}

// AllowOverwrite returns true if new state from a particular source is allowed
// to overwrite existing state from another source
func AllowOverwrite(existing, new Source) bool {
	overflowNegative := overflowNegativeTo(len(defaultSources))
	return overflowNegative(slices.Index(defaultSources, new)) <= overflowNegative(slices.Index(defaultSources, existing))
}

func overflowNegativeTo(infinity int) func(int) int {
	return func(n int) int {
		if n < 0 {
			return infinity
		} else {
			return n
		}
	}
}

var Cell = cell.Module(
	"source",
	"Definitions and priorities of data sources",
	cell.Provide(NewSources),
)

// NewSources returns sources ordered from the most preferred.
func NewSources() Sources {
	return defaultSources
}
