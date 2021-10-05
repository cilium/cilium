// SPDX-License-Identifier: Apache-2.0
// Copyright 2018-2019 Authors of Cilium

package ipcache

import (
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
)

var (
	// idMDMU protects the IdentityMetadata map.
	idMDMU lock.RWMutex
	// IdentityMetadata maps IP prefixes (x.x.x.x/32) to their labels.
	IdentityMetadata = make(map[string]labels.Labels)
)

// UpsertMetadata upserts a given IP and its corresponding labels associated
// with it into the IdentityMetadata map. The given labels are not modified nor
// is its reference saved, as their copied when inserting into the map.
func UpsertMetadata(prefix string, lbls labels.Labels) {
	l := labels.NewLabelsFromModel(nil)
	l.MergeLabels(lbls)

	idMDMU.Lock()
	if cur, ok := IdentityMetadata[prefix]; !ok {
		IdentityMetadata[prefix] = l
	} else {
		l.MergeLabels(cur)
		IdentityMetadata[prefix] = l
	}
	idMDMU.Unlock()
}

// GetIDMetadataByIP returns the associated labels with an IP. The caller must
// not modifying the returned object as it's a live reference to the underlying
// map.
func GetIDMetadataByIP(prefix string) labels.Labels {
	idMDMU.RLock()
	defer idMDMU.RUnlock()
	return IdentityMetadata[prefix]
}
