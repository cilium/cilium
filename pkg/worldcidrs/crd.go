// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package worldcidrs

import (
	"fmt"
	"net/netip"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// loadAllCIDRs retrieves the desired set of encapsulated CIDRs based on the current apiserver configuration
func (m *Manager) loadAllCIDRs(groupStore resource.Store[*v2alpha1.CiliumCIDRGroup]) map[netip.Prefix]bool {
	out := make(map[netip.Prefix]bool, len(m.mapState))
	for _, group := range groupStore.List() {
		annoFound := false
		encap := false
		for k, v := range group.Annotations {
			if k == annotation.HighScaleEncapsulate {
				annoFound = true
				if v == "true" {
					encap = true
					break
				}
			}
		}
		if !annoFound {
			continue
		}

		cidrs := parseCIDRGroup(group)
		for _, cidr := range cidrs {
			if existing, exists := out[cidr]; exists && existing != encap {
				log.WithFields(logrus.Fields{
					logfields.CIDRGroupRef: group.Name,
					logfields.Prefix:       cidr,
				}).Warnf("CIDR has conflicting values for %s", annotation.HighScaleEncapsulate)
			}
			out[cidr] = encap
		}
	}
	return out
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
