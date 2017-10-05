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
	"github.com/cilium/cilium/pkg/maps/cidrmap"
	"github.com/cilium/cilium/pkg/policy/api"
)

// L3PolicyMap is a list of CIDR filters indexable by address/prefixlen
// key format: "address/prefixlen", e.g., "10.1.1.0/24"
//
// L3PolicyMap does no locking internally, so the user is responsible for synchronizing
// between multiple threads when applicable.
type L3PolicyMap struct {
	Map         map[string]net.IPNet // Allowed L3 prefixes
	IPv6Changed bool
	IPv6Count   int // Count of IPv6 prefixes in 'Map'
	IPv4Changed bool
	IPv4Count   int // Count of IPv4 prefixes in 'Map'
}

// Insert places 'cidr' in to map 'm'. Returns `1` if `cidr` is added
// to the map, `0` otherwise
func (m *L3PolicyMap) Insert(cidr string) int {
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
		m.Map[key] = *ipnet
		if ipnet.IP.To4() == nil {
			m.IPv6Count++
			m.IPv6Changed = true
		} else {
			m.IPv4Count++
			m.IPv4Changed = true
		}
		return 1
	}

	return 0
}

// ToBPFData converts map 'm' into string slices 's6' and 's4',
// formatted for insertion into bpf program.
func (m *L3PolicyMap) ToBPFData() (s6, s4 []string) {
	for _, v := range m.Map {
		ip4 := v.IP.To4()
		if ip4 == nil { // IPv6
			s6 = append(s6,
				fmt.Sprintf("{{{__constant_htonl(%#x),__constant_htonl(%#x),__constant_htonl(%#x),__constant_htonl(%#x)}},{{__constant_htonl(%#x),__constant_htonl(%#x),__constant_htonl(%#x),__constant_htonl(%#x)}}}",
					byteorder.HostToNetworkSlice(v.IP[0:4], reflect.Uint32), byteorder.HostToNetworkSlice(v.IP[4:8], reflect.Uint32),
					byteorder.HostToNetworkSlice(v.IP[8:12], reflect.Uint32), byteorder.HostToNetworkSlice(v.IP[12:16], reflect.Uint32),
					byteorder.HostToNetworkSlice(v.Mask[0:4], reflect.Uint32), byteorder.HostToNetworkSlice(v.Mask[4:8], reflect.Uint32),
					byteorder.HostToNetworkSlice(v.Mask[8:12], reflect.Uint32), byteorder.HostToNetworkSlice(v.Mask[12:16], reflect.Uint32)))
		} else {
			s4 = append(s4, fmt.Sprintf("{__constant_htonl(%#x),__constant_htonl(%#x)}", byteorder.HostToNetworkSlice(ip4, reflect.Uint32), byteorder.HostToNetworkSlice(v.Mask, reflect.Uint32)))
		}
	}
	return
}

// PopulateBPF inserts the entries in map 'm' in to 'cidrmap'.
func (m *L3PolicyMap) PopulateBPF(cidrmap *cidrmap.CIDRMap) error {
	for _, value := range m.Map {
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

// DeepCopy makes a duplicate of 'm'.
func (m L3PolicyMap) DeepCopy() L3PolicyMap {
	cpy := L3PolicyMap{
		Map:         make(map[string]net.IPNet, len(m.Map)),
		IPv6Changed: m.IPv6Changed,
		IPv6Count:   m.IPv6Count,
		IPv4Changed: m.IPv4Changed,
		IPv4Count:   m.IPv4Count,
	}
	for k, v := range m.Map {
		cpy.Map[k] = v
	}
	return cpy
}

// L3Policy contains L3 policy maps for ingress and egress.
type L3Policy struct {
	Ingress L3PolicyMap
	Egress  L3PolicyMap
}

// NewL3Policy creates a new L3Policy.
func NewL3Policy() *L3Policy {
	return &L3Policy{
		Ingress: L3PolicyMap{Map: make(map[string]net.IPNet)},
		Egress:  L3PolicyMap{Map: make(map[string]net.IPNet)},
	}
}

// DeepCopy duplicates 'l3'.
func (l3 *L3Policy) DeepCopy() *L3Policy {
	return &L3Policy{
		Ingress: l3.Ingress.DeepCopy(),
		Egress:  l3.Egress.DeepCopy(),
	}
}

// GetModel returns the API model representation of the L3Policy.
func (l3 *L3Policy) GetModel() *models.CIDRPolicy {
	if l3 == nil {
		return nil
	}

	ingress := []string{}
	for _, v := range l3.Ingress.Map {
		ingress = append(ingress, v.String())
	}

	egress := []string{}
	for _, v := range l3.Egress.Map {
		egress = append(egress, v.String())
	}

	return &models.CIDRPolicy{
		Ingress: ingress,
		Egress:  egress,
	}
}

// Validate returns error if the L3 policy might lead to code generation failure
func (l3 *L3Policy) Validate() error {
	if l3 == nil {
		return nil
	}
	if l := len(l3.Egress.Map); l > api.MaxCIDREntries {
		return fmt.Errorf("too many egress L3 entries %d/%d", l, api.MaxCIDREntries)
	}
	if l := len(l3.Ingress.Map); l > api.MaxCIDREntries {
		return fmt.Errorf("too many ingress L3 entries %d/%d", l, api.MaxCIDREntries)
	}
	return nil
}
