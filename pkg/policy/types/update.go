// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"time"

	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/source"
)

// PolicyUpdate is a proposed change to a policy in the PolicyRepository.
type PolicyUpdate struct {
	// The set of rules to be added.
	// Set to nil to delete for the given resource or labels.
	Rules policyapi.Rules

	// Resource provides the object ID for the underlying object that backs
	// this information from 'source'.
	Resource ipcacheTypes.ResourceID

	// Replace if true indicates that existing rules with identical labels should be replaced,
	// and that the set of labels should be taken from the rules.
	ReplaceByLabels bool

	// ReplaceWithLabels, if present, indicates that existing rules with the
	// given LabelArray should be deleted.
	ReplaceWithLabels labels.LabelArray

	// The source of this policy, used for prefix allocation
	Source source.Source

	// The time the policy initially began to be processed in Cilium, such as when the
	// policy was received from the API server.
	ProcessingStartTime time.Time

	// DoneChan, if not nil, will have a single value emitted: the revision of the
	// policy repository when the update has been processed.
	// Thus must be a buffered channel!
	DoneChan chan<- uint64
}
