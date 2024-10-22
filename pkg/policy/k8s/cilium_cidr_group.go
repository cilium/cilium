// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"net/netip"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	cilium_v2_alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/source"
)

// onUpsertCIDRGroup updates the internal cache and,
// if this CIDRGroup is referenced by any policies,
// applies it to the IPCache.
func (p *policyWatcher) onUpsertCIDRGroup(
	cidrGroup *cilium_v2_alpha1.CiliumCIDRGroup,
	apiGroup string,
) {
	defer func() {
		p.k8sResourceSynced.SetEventTimestamp(apiGroup)
	}()
	name := cidrGroup.Name

	oldCidrGroup, ok := p.cidrGroupCache[name]
	if ok && oldCidrGroup.Spec.DeepEqual(&cidrGroup.Spec) {
		return
	}
	p.cidrGroupCache[name] = cidrGroup

	p.applyCIDRGroup(name)
}

// applyCIDRGroup inserts / removes prefixes in the ipcache
// labelled as belonging to the CIDR group.
//
// If the CIDRGroup in question is not referenced by any policies,
// this treats it as being deleted.
func (p *policyWatcher) applyCIDRGroup(name string) {
	oldCIDRs, ok := p.cidrGroupCIDRs[name]
	if !ok {
		oldCIDRs = make(sets.Set[netip.Prefix])
	}
	newCIDRs := make(sets.Set[netip.Prefix])

	// If this CIDR group does not exist, *or* it has no policies referencing it,
	// then pretend it is an empty cidr group.
	cidrGroup, ok := p.cidrGroupCache[name]
	if ok && p.cidrGroupRefs[name] > 0 {
		for i, c := range cidrGroup.Spec.ExternalCIDRs {
			pfx, err := netip.ParsePrefix(string(c))
			if err != nil {
				p.log.WithField(logfields.CIDRGroupRef, name).WithError(err).Warnf("CIDRGroup has invalid CIDR at index %d", i)
				continue
			}
			newCIDRs.Insert(pfx)
		}
	} else if ok {
		p.log.WithField(logfields.CIDRGroupRef, name).Debug("Skipping unreferenced CIDRGroup")
	}

	if newCIDRs.Equal(oldCIDRs) {
		return
	}

	if len(newCIDRs) == 0 {
		delete(p.cidrGroupCIDRs, name)
	} else {
		p.cidrGroupCIDRs[name] = newCIDRs
	}

	// Upsert all net-new prefixes in to the ipcache.
	resourceID := ipcacheTypes.NewResourceID(
		ipcacheTypes.ResourceKindCIDRGroup,
		"",
		name,
	)

	mu := make([]ipcache.MU, 0, len(newCIDRs))
	for newCIDR := range newCIDRs {
		// If we already upserted this, there's no need to do it again.
		if oldCIDRs.Has(newCIDR) {
			oldCIDRs.Delete(newCIDR)
			continue
		}

		// Label this CIDR with:
		// - "reserved:world="
		// - "cidrgroup:io.cilium.groupname/<name>="
		lbls := labels.FromSlice([]labels.Label{api.LabelForCIDRGroupRef(name)})
		lbls.AddWorldLabel(newCIDR.Addr())
		mu = append(mu, ipcache.MU{
			Prefix:   newCIDR,
			Source:   source.Generated,
			Resource: resourceID,
			Metadata: []ipcache.IPMetadata{lbls},
		})
	}
	if len(mu) > 0 {
		p.ipCache.UpsertMetadataBatch(mu...)
	}

	// Remove any CIDRs no longer referenced by this set
	mu = make([]ipcache.MU, 0, len(oldCIDRs))
	for oldCIDR := range oldCIDRs {
		mu = append(mu, ipcache.MU{
			Prefix:   oldCIDR,
			Source:   source.Generated,
			Resource: resourceID,
			Metadata: []ipcache.IPMetadata{labels.Labels{}},
		})
	}
	if len(mu) > 0 {
		p.ipCache.RemoveMetadataBatch(mu...)
	}
}

func (p *policyWatcher) onDeleteCIDRGroup(
	cidrGroupName string,
	apiGroup string,
) {
	delete(p.cidrGroupCache, cidrGroupName)

	// Do not delete refcount here; this may be re-added and we will want
	// to know that it is referenced.

	p.applyCIDRGroup(cidrGroupName)
	p.k8sResourceSynced.SetEventTimestamp(apiGroup)
}

func getCIDRGroupRefs(cnp *types.SlimCNP) []string {
	if cnp.Spec == nil && cnp.Specs == nil {
		return nil
	}

	specs := cnp.Specs
	if cnp.Spec != nil {
		specs = append(specs, cnp.Spec)
	}

	var cidrGroupRefs []string
	for _, spec := range specs {
		for _, ingress := range spec.Ingress {
			for _, rule := range ingress.FromCIDRSet {
				// If CIDR is not set, then we assume CIDRGroupRef is set due
				// to OneOf, even if CIDRGroupRef is empty, as that's still a
				// valid reference (although useless from a user perspective).
				if len(rule.Cidr) == 0 {
					cidrGroupRefs = append(cidrGroupRefs, string(rule.CIDRGroupRef))
				}
			}
		}
		for _, ingress := range spec.IngressDeny {
			for _, rule := range ingress.FromCIDRSet {
				if len(rule.Cidr) == 0 {
					cidrGroupRefs = append(cidrGroupRefs, string(rule.CIDRGroupRef))
				}
			}
		}
		for _, egress := range spec.Egress {
			for _, rule := range egress.ToCIDRSet {
				if len(rule.Cidr) == 0 {
					cidrGroupRefs = append(cidrGroupRefs, string(rule.CIDRGroupRef))
				}
			}
		}
		for _, egress := range spec.EgressDeny {
			for _, rule := range egress.ToCIDRSet {
				if len(rule.Cidr) == 0 {
					cidrGroupRefs = append(cidrGroupRefs, string(rule.CIDRGroupRef))
				}
			}
		}
	}

	return cidrGroupRefs
}
