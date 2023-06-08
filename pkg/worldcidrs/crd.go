// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package worldcidrs

import (
	"fmt"
	"net/netip"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
)

// loadAllCIDRs computes the set of cidrs and their groups that are referenced
// by all WorldCIDRSets.
func (m *Manager) loadAllCIDRs(setStore resource.Store[*v2alpha1.CiliumWorldCIDRSet], groupStore resource.Store[*v2alpha1.CiliumCIDRGroup]) (sets.Set[netip.Prefix], sets.Set[api.CIDRGroupRef]) {
	wantPrefixes := make(sets.Set[netip.Prefix], len(m.mapState))
	groupsInUse := make(sets.Set[api.CIDRGroupRef], len(m.groupsInUse))

	for _, cidrSet := range setStore.List() {
		groupRefs, err := parseCWCIDR(cidrSet)
		if err != nil {
			log.WithError(err).WithField(logfields.CiliumWorldCIDRSetName, cidrSet.Name).
				Warning("Skipping invalid CiliumWorldCIDRSet")
			continue
		}

		for _, groupRef := range groupRefs {
			if groupsInUse.Has(groupRef) {
				continue
			}

			group, _, _ := groupStore.GetByKey(resource.Key{Name: string(groupRef)})
			if group == nil {
				log.WithError(err).WithFields(logrus.Fields{
					logfields.CIDRGroupRef:           groupRef,
					logfields.CiliumWorldCIDRSetName: cidrSet.Name,
				}).Warning("Could not find CiliumCIDRGroup referenced by CiliumWorldCIDRSet")
				continue
			}

			prefixes := parseCIDRGroup(group)
			wantPrefixes.Insert(prefixes...)
		}

		// Capture all referenced group names, even if they don't presently exist, so we
		// resync if they are created / updated / deleted.
		groupsInUse.Insert(groupRefs...)
	}

	return wantPrefixes, groupsInUse
}

func parseCWCIDR(cwcidr *v2alpha1.CiliumWorldCIDRSet) (groupNames []api.CIDRGroupRef, err error) {
	name := cwcidr.ObjectMeta.Name
	if name == "" {
		err = fmt.Errorf("CiliumWorldCIDRSet must have a name")
		return
	}

	if cwcidr.Spec.Encapsulate != nil && *cwcidr.Spec.Encapsulate {
		err = fmt.Errorf("invalid CiliumWorldCIDR: spec.encapsulate must be false")
		return
	}

	return cwcidr.Spec.CIDRGroupRefs, nil
}

func parseCIDRGroup(group *v2alpha1.CiliumCIDRGroup) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(group.Spec.ExternalCIDRs))
	for _, cidrString := range group.Spec.ExternalCIDRs {
		prefix, err := netip.ParsePrefix(string(cidrString))
		if err != nil {
			err := fmt.Errorf("invalid cidr %s: %w", cidrString, err)
			log.WithField(logfields.CIDRGroupRef, group.Name).WithError(err).Warningf("Could not parse CIDR in CiliumCIDRGroup")
			continue
		}
		if prefix.Addr().Is6() {
			log.WithField(logfields.CIDRGroupRef, group.Name).Warning("CiliumCIDRGroup referenced by CiliumWorldCIDRSet contains ipv6 address, currently unsupported")
		}
		prefixes = append(prefixes, prefix)
	}

	return prefixes
}
