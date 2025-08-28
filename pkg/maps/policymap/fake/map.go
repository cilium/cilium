// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

type PolicyKey = policymap.PolicyKey
type PolicyEntry = policymap.PolicyEntry
type PolicyEntryDump = policymap.PolicyEntryDump
type PolicyEntriesDump = policymap.PolicyEntriesDump
type MapStateMap = types.MapStateMap

var _ policymap.PolicyMap = (*fakePolicyMap)(nil)

type fakePolicyMap struct {
	Entries map[PolicyKey]PolicyEntry
}

func NewFakePolicyMap() *fakePolicyMap {
	return &fakePolicyMap{
		Entries: map[PolicyKey]PolicyEntry{},
	}
}

func (pm *fakePolicyMap) Update(key *PolicyKey, entry *PolicyEntry) error {
	pm.Entries[*key] = *entry
	return nil
}

func (pm *fakePolicyMap) DeleteKey(key PolicyKey) error {
	delete(pm.Entries, key)
	return nil
}

func (pm *fakePolicyMap) DeleteEntry(entry *PolicyEntryDump) error {
	delete(pm.Entries, entry.Key)
	return nil
}

func (pm *fakePolicyMap) String() string {
	return "fakepolicymap"
}

func (pm *fakePolicyMap) Dump() (string, error) {
	entries, err := pm.DumpToSlice()
	if err != nil {
		return "", err
	}
	return entries.String(), nil
}

func (pm *fakePolicyMap) DumpToSlice() (PolicyEntriesDump, error) {
	entries := make(PolicyEntriesDump, 0, len(pm.Entries))
	for key, value := range pm.Entries {
		entries = append(entries, PolicyEntryDump{
			Key:         key,
			PolicyEntry: value,
		})
	}
	return entries, nil
}

// Keep this up-to-date with DumpToMapStateMap() from
// pkg/maps/policymap/policymap.go.
func (pm *fakePolicyMap) DumpToMapStateMap() (MapStateMap, error) {
	out := make(MapStateMap)
	for key, val := range pm.Entries {
		// Convert from policymap.Key to policy.Key
		policyKey := types.KeyForDirection(trafficdirection.TrafficDirection(key.TrafficDirection)).
			WithIdentity(identity.NumericIdentity(key.Identity)).
			WithPortProtoPrefix(u8proto.U8proto(key.Nexthdr), key.GetDestPort(), key.GetPortPrefixLen())

		// Convert from policymap.PolicyEntry to policyTypes.MapStateEntry.
		policyVal := types.MapStateEntry{
			Precedence:      val.Precedence,
			ProxyPort:       val.GetProxyPort(),
			AuthRequirement: val.AuthRequirement,
			Cookie:          val.Cookie,
		}.WithDeny(val.IsDeny())
		// if policymapEntry has invalid prefix length, force update by storing as an
		// invalid MapStateEntry
		if !val.IsValid(&key) {
			policyVal.Invalidate()
		}
		out[policyKey] = policyVal
	}
	return out, nil
}

func (pm *fakePolicyMap) MaxEntries() uint32 { return 1024 }
func (pm *fakePolicyMap) Close() error       { return nil }
