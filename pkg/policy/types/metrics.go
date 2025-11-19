// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

const (
	// LabelSelectorClass indicates the class of selector being measured
	LabelSelectorClass = "class"

	// LabelValueSCFQDN is used for regular security identities
	// shared between all nodes in the cluster.
	LabelValueSCFQDN = "fqdn"

	// LabelValueSCCluster is used for the cluster entity.
	LabelValueSCCluster = "cluster"

	// LabelValueSCWorld is used for the world entity.
	LabelValueSCWorld = "world"

	// LabelValueSCOther is used for security identities allocated locally
	// on the current node.
	LabelValueSCOther = "other"

	// LabelValueSCTypePeer is used for the normal selector cache
	LabelValueSCTypePeer = "peer"

	// LabelValueSCOperationAddSelector is used for the operation that adds a new selector
	LabelValueSCOperationAddSelector = "add_selector"

	// LabelValueSCOperationRemoveSelector is used for the operation that removes a selector
	LabelValueSCOperationRemoveSelector = "remove_selector"

	// LabelValueSCOperationIdentityUpdates is used for the operation that updates one or more identities in the cache
	LabelValueSCOperationIdentityUpdates = "identity_updates"

	// LabelValueSCOperation is used for the actual Selector Cache Operation duration
	LabelValueSCOperation = "operation"

	// LabelValueSCOperationLock is used for the actual lock time during the Selector Cache Operation duration
	LabelValueSCOperationLock = "lock"
)

type PolicyMetrics interface {
	AddRule(r PolicyEntry)
	DelRule(r PolicyEntry)
}
