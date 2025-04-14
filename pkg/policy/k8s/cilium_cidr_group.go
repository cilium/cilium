// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"maps"
	"net/netip"

	"k8s.io/apimachinery/pkg/util/sets"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/source"
)

// onUpsertCIDRGroup updates the internal cache and,
// if this CIDRGroup is referenced by any policies,
// applies it to the IPCache.
func (p *policyWatcher) onUpsertCIDRGroup(
	cidrGroup *cilium_v2.CiliumCIDRGroup,
	apiGroup string,
) {
	defer func() {
		p.k8sResourceSynced.SetEventTimestamp(apiGroup)
	}()
	name := cidrGroup.Name

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
	lbls := labels.Labels{}

	// If CIDRGroup isn't deleted; populate newCIDRs
	if cidrGroup, ok := p.cidrGroupCache[name]; ok {
		lbls = labels.Map2Labels(utils.RemoveCiliumLabels(cidrGroup.Labels), labels.LabelSourceCIDRGroup)
		lbl := api.LabelForCIDRGroupRef(name)
		lbls[lbl.Key] = lbl

		for i, c := range cidrGroup.Spec.ExternalCIDRs {
			pfx, err := netip.ParsePrefix(string(c))
			if err != nil {
				p.log.Warn(
					"CIDRGroup has invalid CIDR",
					logfields.Error, err,
					logfields.CIDRGroupRef, name,
					logfields.Index, i,
				)
				continue
			}
			newCIDRs.Insert(pfx)
		}
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

	// Label this CIDR with:
	// - "reserved:world-ipv4=" or "reserved:world-ipv6="
	// - "cidrgroup:io.cilium.groupname/<name>="
	// - "cidrgroup:<key>=<val>" from the group's labels
	mu := make([]ipcache.MU, 0, len(newCIDRs))
	for newCIDR := range newCIDRs {
		if oldCIDRs.Has(newCIDR) {
			// Remove new CIDR from set of stale CIDRs.
			oldCIDRs.Delete(newCIDR)
			// Note: we cannot short-cut injecting newCIDR; labels may have changed.
		}
		cidrLbls := maps.Clone(lbls)
		cidrLbls.AddWorldLabel(newCIDR.Addr())

		mu = append(mu, ipcache.MU{
			Prefix:   cmtypes.NewLocalPrefixCluster(newCIDR),
			Source:   source.Generated,
			Resource: resourceID,
			Metadata: []ipcache.IPMetadata{cidrLbls},
		})
	}
	if len(mu) > 0 {
		p.ipCache.UpsertMetadataBatch(mu...)
	}

	// Remove any stale CIDRs no longer referenced by this set
	mu = make([]ipcache.MU, 0, len(oldCIDRs))
	for oldCIDR := range oldCIDRs {
		mu = append(mu, ipcache.MU{
			Prefix:   cmtypes.NewLocalPrefixCluster(oldCIDR),
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
	p.applyCIDRGroup(cidrGroupName)
	p.k8sResourceSynced.SetEventTimestamp(apiGroup)
}
