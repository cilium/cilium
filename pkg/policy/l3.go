// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"net"
	"sort"
	"strconv"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
)

// CIDRPolicyMapRule holds a L3 (CIDR) prefix and the rule labels that allow it.
type CIDRPolicyMapRule struct {
	Prefix           net.IPNet
	DerivedFromRules labels.LabelArrayList
}

// CIDRPolicyMap is a list of CIDR filters indexable by address/prefixlen
// key format: "address/prefixlen", e.g., "10.1.1.0/24"
// Each prefix struct also includes the rule labels that allowed it.
//
// CIDRPolicyMap does no locking internally, so the user is responsible for synchronizing
// between multiple threads when applicable.
type CIDRPolicyMap struct {
	Map map[string]*CIDRPolicyMapRule // Allowed L3 (CIDR) prefixes

	IPv6PrefixCount map[int]int // Count of IPv6 prefixes in 'Map' indexed by prefix length
	IPv4PrefixCount map[int]int // Count of IPv4 prefixes in 'Map' indexed by prefix length
}

// GetDefaultPrefixLengths returns the set of prefix lengths for handling
// CIDRs that are unconditionally mapped to identities, ie for the reserved
// identities 'host', 'world'.
func GetDefaultPrefixLengths() (s6 []int, s4 []int) {
	// These *must* be in the order of longest prefix to shortest, as the
	// LPM implementation on older kernels depends on this ordering.
	s6 = []int{net.IPv6len * 8, 0}
	s4 = []int{net.IPv4len * 8, 0}
	return
}

// Insert places 'cidr' and its corresponding rule labels into map 'm'. Returns
// `1` if `cidr` is added to the map, `0` otherwise.
func (m *CIDRPolicyMap) Insert(cidr string, ruleLabels labels.LabelArray) int {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		var mask net.IPMask
		ip := net.ParseIP(cidr)
		// Use default CIDR mask for the address if the bits in the address
		// after the mask are all zeroes.
		ip4 := ip.To4()
		if ip4 == nil {
			mask = net.CIDRMask(128, 128)
		} else { // IPv4
			ip = ip4
			mask = ip.DefaultMask() // IP address class based mask (/8, /16, or /24)
			if !ip.Equal(ip.Mask(mask)) {
				// IPv4 with non-zeroes after the subnetwork, use full mask.
				mask = net.CIDRMask(32, 32)
			}
		}
		ipnet = &net.IPNet{IP: ip, Mask: mask}
	}

	ones, _ := ipnet.Mask.Size()

	key := ipnet.IP.String() + "/" + strconv.Itoa(ones)
	if _, found := m.Map[key]; !found {
		m.Map[key] = &CIDRPolicyMapRule{Prefix: *ipnet, DerivedFromRules: labels.LabelArrayList{ruleLabels}}
		if ipnet.IP.To4() == nil {
			m.IPv6PrefixCount[ones]++
		} else {
			m.IPv4PrefixCount[ones]++
		}
		return 1
	} else {
		m.Map[key].DerivedFromRules = append(m.Map[key].DerivedFromRules, ruleLabels)
	}

	return 0
}

// CIDRPolicy contains L3 (CIDR) policy maps for ingress.
//
// This is not used for map entry generation; It has two uses:
// * On older kernels, generate the set of CIDR prefix lengths that
//   are necessary to implement an LPM
// * Reflect desired state of the CIDR policy in the API.
type CIDRPolicy struct {
	Ingress CIDRPolicyMap
	Egress  CIDRPolicyMap
}

// NewCIDRPolicy creates a new CIDRPolicy.
func NewCIDRPolicy() (policy *CIDRPolicy) {
	policy = &CIDRPolicy{
		Ingress: CIDRPolicyMap{
			Map:             make(map[string]*CIDRPolicyMapRule),
			IPv6PrefixCount: make(map[int]int),
			IPv4PrefixCount: make(map[int]int),
		},
		Egress: CIDRPolicyMap{
			Map:             make(map[string]*CIDRPolicyMapRule),
			IPv6PrefixCount: make(map[int]int),
			IPv4PrefixCount: make(map[int]int),
		},
	}
	// Add a default reference to the default {host, cluster, world} prefix
	// to ensure that ToBPFData() always serializes these lengths for LPM.
	s6, s4 := GetDefaultPrefixLengths()
	for _, i := range s6 {
		policy.Egress.IPv6PrefixCount[i] = 0
		policy.Ingress.IPv6PrefixCount[i] = 0
	}
	for _, i := range s4 {
		policy.Egress.IPv4PrefixCount[i] = 0
		policy.Ingress.IPv4PrefixCount[i] = 0
	}
	return
}

// ToBPFData converts the ingress and egress cidr map into int slices 's6'
// (IPv6) and 's4' (IPv4), formatted for insertion into bpf program as prefix
// lengths.
//
// Note that this will always include the CIDR prefix lengths for host (eg /32
// for host), cluster (typically /8 or /64), and world (/0).
//
// FIXME: Move this function out of policy into a datapath specific package
func (cp *CIDRPolicy) ToBPFData() (s6, s4 []int) {
	s6duplicates, s4duplicates := map[int]bool{}, map[int]bool{}

	for _, m := range []CIDRPolicyMap{cp.Ingress, cp.Egress} {
		for p := range m.IPv6PrefixCount {
			if _, ok := s6duplicates[p]; !ok {
				s6 = append(s6, p)
				s6duplicates[p] = true
			}
		}
		for p := range m.IPv4PrefixCount {
			if _, ok := s4duplicates[p]; !ok {
				s4 = append(s4, p)
				s4duplicates[p] = true
			}
		}
	}

	// The datapath expects longest-to-shortest prefixes so that it can
	// clear progressively more bits with a single load of the address.
	sort.Sort(sort.Reverse(sort.IntSlice(s6)))
	sort.Sort(sort.Reverse(sort.IntSlice(s4)))
	return
}

// GetModel returns the API model representation of the CIDRPolicy.
func (cp *CIDRPolicy) GetModel() *models.CIDRPolicy {
	if cp == nil {
		return nil
	}

	ingress := []*models.PolicyRule{}
	for _, v := range cp.Ingress.Map {
		ingress = append(ingress, &models.PolicyRule{
			Rule:             v.Prefix.String(),
			DerivedFromRules: v.DerivedFromRules.GetModel(),
		})
	}

	egress := []*models.PolicyRule{}
	for _, v := range cp.Egress.Map {
		egress = append(egress, &models.PolicyRule{
			Rule:             v.Prefix.String(),
			DerivedFromRules: v.DerivedFromRules.GetModel(),
		})
	}

	return &models.CIDRPolicy{
		Ingress: ingress,
		Egress:  egress,
	}
}

// Validate returns error if the CIDR policy might lead to code generation failure
func (cp *CIDRPolicy) Validate() error {
	return nil
}
