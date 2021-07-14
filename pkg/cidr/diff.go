// SPDX-License-Identifier: Apache-2.0
// Copyright 2019 Authors of Cilium

package cidr

func createIPNetMap(list []*CIDR) map[string]*CIDR {
	m := map[string]*CIDR{}
	for _, c := range list {
		if c != nil {
			m[c.String()] = c
		}
	}
	return m
}

func listMissingIPNets(existing map[string]*CIDR, new []*CIDR) (missing []*CIDR) {
	for _, c := range new {
		if c != nil {
			if _, ok := existing[c.String()]; !ok {
				missing = append(missing, c)
			}
		}
	}
	return
}

// DiffCIDRLists compares an old and new list of CIDRs and returns the list of
// removed and added CIDRs
func DiffCIDRLists(old, new []*CIDR) (add, remove []*CIDR) {
	add = listMissingIPNets(createIPNetMap(old), new)
	remove = listMissingIPNets(createIPNetMap(new), old)
	return
}
