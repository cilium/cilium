// Copyright 2019 Authors of Cilium
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
