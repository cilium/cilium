// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/types"

	k8sCiliumUtils "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/policy"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

type overflowTestPolicyMap struct {
	entries    map[policymap.PolicyKey]policymap.PolicyEntry
	stats      map[policymap.PolicyKey]policymap.StatsValue
	maxEntries uint32
}

type overflowPolicyMapPressureUpdater struct{}

func (overflowPolicyMapPressureUpdater) Update(PolicyMapPressureEvent) {}
func (overflowPolicyMapPressureUpdater) Remove(uint16)                 {}

func newOverflowTestPolicyMap(maxEntries uint32) *overflowTestPolicyMap {
	return &overflowTestPolicyMap{
		entries:    map[policymap.PolicyKey]policymap.PolicyEntry{},
		stats:      map[policymap.PolicyKey]policymap.StatsValue{},
		maxEntries: maxEntries,
	}
}

func (pm *overflowTestPolicyMap) Update(key *policymap.PolicyKey, entry *policymap.PolicyEntry) error {
	if _, exists := pm.entries[*key]; !exists && len(pm.entries) >= int(pm.maxEntries) {
		return unix.ENOSPC
	}
	pm.entries[*key] = *entry
	return nil
}

func (pm *overflowTestPolicyMap) DeleteKey(key policymap.PolicyKey) error {
	delete(pm.entries, key)
	delete(pm.stats, key)
	return nil
}

func (pm *overflowTestPolicyMap) DeleteEntry(entry *policymap.PolicyEntryDump) error {
	return pm.DeleteKey(entry.Key)
}

func (pm *overflowTestPolicyMap) String() string {
	return "overflow-test-policy-map"
}

func (pm *overflowTestPolicyMap) Dump() (string, error) {
	return "", nil
}

func (pm *overflowTestPolicyMap) DumpToSlice() (policymap.PolicyEntriesDump, error) {
	entries := make(policymap.PolicyEntriesDump, 0, len(pm.entries))
	for key, value := range pm.entries {
		entries = append(entries, policymap.PolicyEntryDump{
			Key:         key,
			PolicyEntry: value,
			StatsValue:  pm.stats[key],
		})
	}
	return entries, nil
}

func (pm *overflowTestPolicyMap) DumpToMapStateMap() (policytypes.MapStateMap, error) {
	dump, err := pm.DumpToSlice()
	if err != nil {
		return nil, err
	}
	current, _ := currentPolicyMapState(dump)
	return current, nil
}

func (pm *overflowTestPolicyMap) MaxEntries() uint32 { return pm.maxEntries }
func (pm *overflowTestPolicyMap) Close() error       { return nil }

var _ policymap.PolicyMap = (*overflowTestPolicyMap)(nil)

func testEndpointPolicy(t *testing.T, logger *slog.Logger, entries policy.MapStateMap) *policy.EndpointPolicy {
	t.Helper()
	repo := policy.NewPolicyRepository(logger, nil, nil, nil, nil, testpolicy.NewPolicyMetricsNoop())
	epPolicy := policy.NewEndpointPolicy(logger, repo)
	epPolicy.CopyMapStateFrom(entries)
	return epPolicy
}

func TestPolicyMapOverflowSyncUsesHeuristics(t *testing.T) {
	logger := hivetest.Logger(t)
	testMap := newOverflowTestPolicyMap(3)

	trafficKey := policy.IngressKey().WithIdentity(1001).WithTCPPort(80)
	sctpCurrentKey := policy.IngressKey().WithIdentity(1002).WithSCTPPort(80)
	udpCurrentKey := policy.IngressKey().WithIdentity(1003).WithUDPPort(80)
	tcpNewKey := policy.IngressKey().WithIdentity(1004).WithTCPPort(80)
	sctpNewKey := policy.IngressKey().WithIdentity(1005).WithSCTPPort(80)

	allowEntry := policytypes.AllowEntry()
	for _, key := range []policy.Key{trafficKey, sctpCurrentKey, udpCurrentKey} {
		pmKey := policymap.NewKeyFromPolicyKey(key)
		pmEntry := policymap.NewEntryFromPolicyEntry(pmKey, allowEntry)
		require.NoError(t, testMap.Update(&pmKey, &pmEntry))
	}
	testMap.stats[policymap.NewKeyFromPolicyKey(trafficKey)] = policymap.StatsValue{Packets: 1}

	desired := policy.MapStateMap{
		trafficKey:     allowEntry,
		sctpCurrentKey: allowEntry,
		udpCurrentKey:  allowEntry,
		tcpNewKey:      allowEntry,
		sctpNewKey:     allowEntry,
	}

	ep := &Endpoint{
		ID:                       123,
		policyMap:                testMap,
		desiredPolicy:            testEndpointPolicy(t, logger, desired),
		realizedPolicy:           testEndpointPolicy(t, logger, nil),
		PolicyMapPressureUpdater: overflowPolicyMapPressureUpdater{},
	}
	ep.UpdateLogger(nil)

	err := ep.syncPolicyMap()
	require.NoError(t, err)

	got, err := testMap.DumpToMapStateMap()
	require.NoError(t, err)
	require.Contains(t, got, trafficKey, "entry with traffic should be retained first")
	require.Contains(t, got, udpCurrentKey, "TCP/UDP and existing entry should be retained")
	require.Contains(t, got, tcpNewKey, "TCP should be preferred over SCTP when space remains")
	require.NotContains(t, got, sctpCurrentKey, "SCTP should lose to TCP/UDP entries")
	require.NotContains(t, got, sctpNewKey, "SCTP without traffic or existing state should be omitted")
	require.Len(t, got, int(testMap.MaxEntries()))
}

func TestPolicyMapOverflowIgnoresUnavailableTrafficStats(t *testing.T) {
	key := policy.IngressKey().WithIdentity(1001).WithTCPPort(80)
	allowEntry := policytypes.AllowEntry()
	pmKey := policymap.NewKeyFromPolicyKey(key)
	pmEntry := policymap.NewEntryFromPolicyEntry(pmKey, allowEntry)

	_, traffic := currentPolicyMapState(policymap.PolicyEntriesDump{
		{
			Key:         pmKey,
			PolicyEntry: pmEntry,
			StatsValue: policymap.StatsValue{
				Packets: policymap.StatNotAvailable,
				Bytes:   policymap.StatNotAvailable,
			},
		},
	})
	require.False(t, traffic[key])
}

func TestPolicyMapOverflowPrioritizesCCNPOverCNP(t *testing.T) {
	cnpKey := policy.IngressKey().WithIdentity(2001).WithTCPPort(80)
	ccnpKey := policy.IngressKey().WithIdentity(2002).WithTCPPort(80)
	allowEntry := policytypes.AllowEntry()
	desired := policy.MapStateMap{
		cnpKey:  allowEntry,
		ccnpKey: allowEntry,
	}

	cnpLabels := labels.LabelArrayList{
		k8sCiliumUtils.GetPolicyLabels("default", "cnp", types.UID("cnp"), k8sCiliumUtils.ResourceTypeCiliumNetworkPolicy),
	}
	ccnpLabels := labels.LabelArrayList{
		k8sCiliumUtils.GetPolicyLabels("", "ccnp", types.UID("ccnp"), k8sCiliumUtils.ResourceTypeCiliumClusterwideNetworkPolicy),
	}

	prioritized := prioritizedPolicyMapEntries(desired, nil, nil, func(key policy.Key) (labels.LabelArrayList, bool) {
		switch key {
		case cnpKey:
			return cnpLabels, true
		case ccnpKey:
			return ccnpLabels, true
		default:
			return nil, false
		}
	})
	require.Len(t, prioritized, 2)
	require.Equal(t, ccnpKey, prioritized[0].key)
	require.Equal(t, cnpKey, prioritized[1].key)
}
