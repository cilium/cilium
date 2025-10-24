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
)

type PolicyMetrics interface {
	AddRule(r PolicyEntry)
	DelRule(r PolicyEntry)
}
