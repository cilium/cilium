// Copyright 2018 Authors of Cilium
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

package fqdn

import (
	"crypto/sha512"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

// DNSLookupDefaultResolver runs a DNS lookup for every name in dnsNames
// sequentially and synchronously using the net.DefaultResolver. It will
// return:
// DNSIPs: a map of DNS names to their IPs (only contains successful lookups)
// DNSErrors: a map of DNS names to lookup errors.
// It is used by DNSPoller when no alternative LookupDNSNames is provided
func DNSLookupDefaultResolver(dnsNames []string) (DNSIPs map[string][]net.IP, DNSErrors map[string]error) {
	DNSIPs = make(map[string][]net.IP)
	DNSErrors = make(map[string]error)

	for _, dnsName := range dnsNames {
		lookupIPs, err := net.LookupIP(dnsName)
		if err != nil {
			DNSErrors[dnsName] = err
			continue
		}
		DNSIPs[dnsName] = lookupIPs
	}

	return DNSIPs, DNSErrors
}

// getUUIDFromRuleLabels returns the value of the UUID label
func getUUIDFromRuleLabels(rule *api.Rule) (uuid string) {
	return rule.Labels.Get(uuidLabelSearchKey)
}

// generateUUIDLabel builds a UUID label to unique a rule on PolicyAdd, it is
// consistent over the labels passed in.
// It sorts a copy of the lbls array, and returns a hash
// TODO: this function is a frankenstein mix of labels.Labels.SortedList and
// SHA256Sum, neither of this exist on labels.LabelArray and there is no
// conversion function that won't be even less efficient. fix
func generateUUIDLabel(lbls labels.LabelArray) (id *labels.Label) {
	sorted := make([]string, len(lbls)) // copy uses len(dst) not cap!
	for _, lbl := range lbls {
		sorted = append(sorted, lbl.String())
	}
	sort.Strings(sorted)

	data := []byte(strings.Join(sorted, ""))
	uuid := fmt.Sprintf("%x", sha512.Sum512_256(data))

	return &labels.Label{
		Key:    generatedLabelNameUUID,
		Value:  uuid,
		Source: labels.LabelSourceCiliumGenerated,
	}
}

// injectToCIDRSetRules adds a ToCIDRSets section to the rule with all ToFQDN
// targets resolved to IPs from dnsNames.
// Pre-existing rules in ToCIDRSet are preserved.
func injectToCIDRSetRules(rule *api.Rule, dnsNames map[string][]net.IP) (namesMissingIPs []string) {
	missing := make(map[string]struct{}) // a set to dedup missing dnsNames

	// Add CIDR rules
	// we need to edit Egress[*] in-place
	for egressIdx := range rule.Egress {
		egressRule := &rule.Egress[egressIdx]

		// Generate CIDR rules for each FQDN
		for _, ToFQDN := range egressRule.ToFQDNs {
			dnsName := ToFQDN.MatchName
			IPs, present := dnsNames[dnsName]
			if !present {
				missing[dnsName] = struct{}{}
			}

			egressRule.ToCIDRSet = append(egressRule.ToCIDRSet, ipsToRules(IPs)...)
		}
	}

	for dnsName := range missing {
		namesMissingIPs = append(namesMissingIPs, dnsName)
	}

	return namesMissingIPs
}

// stripeToCIDRSet ensures no ToCIDRSet is nil when ToFQDNs is non-nil
func stripToCIDRSet(rule *api.Rule) {
	for i := range rule.Egress {
		egressRule := &rule.Egress[i]
		if len(egressRule.ToFQDNs) > 0 {
			egressRule.ToCIDRSet = nil
		}
	}
}

// ipsToRules generates CIDRRules for the IPs passed in.
func ipsToRules(ips []net.IP) (cidrRules []api.CIDRRule) {
	for _, ip := range ips {
		rule := api.CIDRRule{ExceptCIDRs: make([]api.CIDR, 0)}
		rule.Generated = true
		if ip.To4() != nil {
			rule.Cidr = api.CIDR(ip.String() + "/32")
		} else {
			rule.Cidr = api.CIDR(ip.String() + "/128")
		}

		cidrRules = append(cidrRules, rule)
	}

	return cidrRules
}

// hasToFQDN indicates whether a ToFQDN rule exists in the api.Rule
func hasToFQDN(rule *api.Rule) bool {
	for _, egressRule := range rule.Egress {
		if len(egressRule.ToFQDNs) > 0 {
			return true
		}
	}

	return false
}

// sortedIPsAreEqual compares two lists of sorted IPs. If any differ it returns
// false.
func sortedIPsAreEqual(a, b []net.IP) bool {
	// the IP set is definitely different if the lengths are different
	if len(a) != len(b) {
		return false
	}

	// lengths are equal, so each member in one set must be in the other
	// Note: we sorted fullNewIPs above, and sorted oldIPs when they were
	// inserted in this function, previously.
	// If any IPs at the same index differ, updated = true.
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}
