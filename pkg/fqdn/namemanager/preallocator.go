// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namemanager

import (
	"context"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
)

// processSelectorChanges allocates and deallocates identities for selectors.
//
// This must be in a separate queue, as this involves updating policy maps
// which may deadlock if the namemanager lock is held.
// So, we allocate and deallocate asynchronously.
//
// The goal is to reduce tail latency of DNS responses. If a response comes in
// for which an identity is already allocated, then we can write that new IP
// to the ipcache but skip updating policy maps. This is much more efficient,
// as updating policy maps involves synchronizing across all endpoints.
//
// Since we only allocate an identity per-fqdn-selector, as long as there are no
// overlapping selectors, a given IP will not have to allocate an identity.
func (n *manager) processSelectorChanges(ctx context.Context, change selectorChange) error {
	lblss := labelsForSelector(n.params.Config.EnableIPv4, n.params.Config.EnableIPv6, change.sel)
	if change.added {
		for _, lbls := range lblss {

			id, _, err := n.params.Allocator.AllocateLocalIdentity(lbls, true, 0)
			if err != nil {
				n.logger.Error("failed to preallocate FQDN identity",
					logfields.Error, err,
					logfields.Labels, lbls)
			} else {
				n.logger.Debug("preallocated FQDN identity",
					logfields.Identity, id)
			}
		}
	} else {
		for _, lbls := range lblss {
			id := n.params.Allocator.LookupIdentity(ctx, lbls)
			if id == nil {
				n.logger.Error("BUG: tried to release non-existent FQDN identity!",
					logfields.Labels, lbls)
				continue
			}
			released, err := n.params.Allocator.Release(ctx, id, true)
			if err != nil {
				// this should not actually fail, given that the identities are local.
				n.logger.Error("BUG: failed to release FQDN identity",
					logfields.Error, err,
					logfields.Identity, id)
			} else {
				n.logger.Debug("released FQDN identity",
					logfields.Identity, id,
					logfields.Released, released)
			}
		}
	}

	return nil
}

func labelsForSelector(v4, v6 bool, sel api.FQDNSelector) []labels.Labels {
	lbl := sel.IdentityLabel()
	out := make([]labels.Labels, 0, 2)
	if v4 && v6 {
		l4 := labels.NewFrom(labels.LabelWorldIPv4)
		l4[lbl.Key] = lbl
		out = append(out, l4)

		l6 := labels.NewFrom(labels.LabelWorldIPv6)
		l6[lbl.Key] = lbl
		out = append(out, l6)
	} else {
		lw := labels.NewFrom(labels.LabelWorld)
		lw[lbl.Key] = lbl
		out = append(out, lw)
	}
	return out
}
