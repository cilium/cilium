// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package source

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
)

// AllowOverwrite returns true if new state from a particular source is allowed
// to overwrite existing state from another source
func AllowOverwrite(existing, new Source) bool {
	switch existing {

	// KubeAPIServer state can only be overwritten by other kube-apiserver
	// state.
	case KubeAPIServer:
		return new == KubeAPIServer

	// Local state can only be overwritten by other local state or
	// kube-apiserver state.
	case Local:
		return new == Local || new == KubeAPIServer

	// KVStore can be overwritten by other kvstore, local state, or
	// kube-apiserver state.
	case KVStore:
		return new == KVStore || new == Local || new == KubeAPIServer

	// Custom-resource state can be overwritten by other CRD, kvstore,
	// local or kube-apiserver state.
	case CustomResource:
		return new == CustomResource || new == KVStore || new == Local || new == KubeAPIServer

	// Kubernetes state can be overwritten by everything except clustermesh,
	// local API, generated, restored and unspecified state.
	case Kubernetes:
		return new != ClusterMesh && new != LocalAPI && new != Generated && new != Restored && new != Unspec

	// ClusterMesh state can be overwritten by everything except local API,
	// generated, restored and unspecified state.
	case ClusterMesh:
		return new != LocalAPI && new != Generated && new != Restored && new != Unspec

	// Local API state can be overwritten by everything except restored,
	// generated and unspecified state
	case LocalAPI:
		return new != Generated && new != Restored && new != Unspec

	// Generated can be overwritten by everything except by Restored and
	// Unspecified
	case Generated:
		return new != Restored && new != Unspec

	// Restored can be overwritten by everything except by Unspecified
	case Restored:
		return new != Unspec

	// Unspecified state can be overwritten by everything
	case Unspec:
		return true
	}

	return true
}
