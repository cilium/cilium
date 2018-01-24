// Copyright 2016-2017 Authors of Cilium
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
	"fmt"
	"net"
	"reflect"
	"strconv"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/cidrmap"
	"github.com/cilium/cilium/pkg/policy/api"
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
	Map       map[string]*CIDRPolicyMapRule // Allowed L3 (CIDR) prefixes
	IPv6Count int                           // Count of IPv6 prefixes in 'Map'
	IPv4Count int                           // Count of IPv4 prefixes in 'Map'
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
			m.IPv6Count++
		} else {
			m.IPv4Count++
		}
		return 1
	} else {
		m.Map[key].DerivedFromRules = append(m.Map[key].DerivedFromRules, ruleLabels)
	}

	return 0
}

// ToBPFData converts map 'm' into string slices 's6' (IPv6) and 's4' (IPv4),
// formatted for insertion into bpf program.
func (m *CIDRPolicyMap) ToBPFData() (s6, s4 []string) {
	for _, v := range m.Map {
		ipnet := v.Prefix
		ip4 := ipnet.IP.To4()
		if ip4 == nil { // IPv6
			s6 = append(s6,
				fmt.Sprintf("{{{__constant_htonl(%#x),__constant_htonl(%#x),__constant_htonl(%#x),__constant_htonl(%#x)}},{{__constant_htonl(%#x),__constant_htonl(%#x),__constant_htonl(%#x),__constant_htonl(%#x)}}}",
					byteorder.HostToNetworkSlice(ipnet.IP[0:4], reflect.Uint32), byteorder.HostToNetworkSlice(ipnet.IP[4:8], reflect.Uint32),
					byteorder.HostToNetworkSlice(ipnet.IP[8:12], reflect.Uint32), byteorder.HostToNetworkSlice(ipnet.IP[12:16], reflect.Uint32),
					byteorder.HostToNetworkSlice(ipnet.Mask[0:4], reflect.Uint32), byteorder.HostToNetworkSlice(ipnet.Mask[4:8], reflect.Uint32),
					byteorder.HostToNetworkSlice(ipnet.Mask[8:12], reflect.Uint32), byteorder.HostToNetworkSlice(ipnet.Mask[12:16], reflect.Uint32)))
		} else {
			s4 = append(s4, fmt.Sprintf("{__constant_htonl(%#x),__constant_htonl(%#x)}", byteorder.HostToNetworkSlice(ip4, reflect.Uint32), byteorder.HostToNetworkSlice(ipnet.Mask, reflect.Uint32)))
		}
	}
	return
}

// PopulateBPF inserts the entries in m into cidrmap. Returns an error
// if the insertion of an entry of cidrmap into m fails.
func (m *CIDRPolicyMap) PopulateBPF(cidrmap *cidrmap.CIDRMap) error {
	for _, cidrPolicyRule := range m.Map {
		value := cidrPolicyRule.Prefix
		if value.IP.To4() == nil {
			if cidrmap.AddrSize != 16 {
				continue
			}
		} else {
			if cidrmap.AddrSize != 4 {
				continue
			}
		}
		err := cidrmap.InsertCIDR(value)
		if err != nil {
			return err
		}
	}
	return nil
}

// CIDRPolicy contains L3 (CIDR) policy maps for ingress and egress.
type CIDRPolicy struct {
	Ingress CIDRPolicyMap
	Egress  CIDRPolicyMap
}

// NewCIDRPolicy creates a new CIDRPolicy.
func NewCIDRPolicy() *CIDRPolicy {
	return &CIDRPolicy{
		Ingress: CIDRPolicyMap{
			Map: make(map[string]*CIDRPolicyMapRule),
		},
		Egress: CIDRPolicyMap{
			Map: make(map[string]*CIDRPolicyMapRule),
		},
	}
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
	if cp == nil {
		return nil
	}
	if l := len(cp.Egress.Map); l > api.MaxCIDREntries {
		return fmt.Errorf("too many egress CIDR entries %d/%d", l, api.MaxCIDREntries)
	}
	if l := len(cp.Ingress.Map); l > api.MaxCIDREntries {
		return fmt.Errorf("too many ingress CIDR entries %d/%d", l, api.MaxCIDREntries)
	}
	return nil
}
