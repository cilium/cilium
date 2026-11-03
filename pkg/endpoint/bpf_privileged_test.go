// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/testutils"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

func TestPrivilegedEndpointPolicySync(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("shared policy enabled=%t", enabled), func(t *testing.T) {
			testutils.PrivilegedTest(t)
			logger := hivetest.Logger(t)
			bpf.CheckOrMountFS(logger, "")
			require.NoError(t, rlimit.RemoveMemlock())
			_ = os.Remove(bpf.MapPath(logger, policymap.SharedPolicyMapName))
			_ = os.Remove(bpf.MapPath(logger, policymap.PolicyOverlayMapName))

			var policyMapFactory policymap.Factory
			h := hive.New(
				registry.Cell,
				policymap.Cell,
				cell.Provide(func() *option.DaemonConfig {
					return &option.DaemonConfig{EnableSharedPolicy: enabled}
				}),
				cell.Invoke(func(p policymap.Factory) { policyMapFactory = p }),
			)
			require.NoError(t, h.Start(logger, context.Background()))
			t.Cleanup(func() { require.NoError(t, h.Stop(logger, context.Background())) })
			var shared, overlay *bpf.Map
			var err error
			if enabled {
				shared, err = bpf.OpenMap(bpf.MapPath(logger, policymap.SharedPolicyMapName), &policymap.SharedPolicyKey{}, &policymap.PolicyEntry{})
				require.NoError(t, err)
				t.Cleanup(func() { shared.Close() })
				overlay, err = bpf.OpenMap(bpf.MapPath(logger, policymap.PolicyOverlayMapName), &policymap.OverlayKey{}, &policymap.OverlayValue{})
				require.NoError(t, err)
				t.Cleanup(func() { overlay.Close() })
			}

			repo := policy.NewPolicyRepository(logger, cmtypes.DefaultClusterInfo, nil, nil, nil, nil, testpolicy.NewPolicyMetricsNoop())

			// Create endpoint
			pressure := &policyMapPressureRecorder{}
			ep := &Endpoint{
				PolicyMapPressureUpdater: pressure,
				ID:                       42,
				policyMapFactory:         policyMapFactory,
			}
			ep.UpdateLogger(nil)

			// Create desired policy state directly
			desiredPolicy := policy.NewEndpointPolicy(slog.Default(), repo)
			m := policytypes.MapStateMap{
				// 1. L4 Egress Redirection (Proxy)
				policytypes.KeyForDirection(1).
					WithIdentity(200).
					WithPortProtoPrefix(6, 443, 16): policytypes.MapStateEntry{
					ProxyPort:  15001,
					Precedence: 2,
				},
				// 2. L3 Egress Allow (All ports)
				policytypes.KeyForDirection(1).
					WithIdentity(201): policytypes.AllowEntry(),
				// 3. L4 Egress Allow (Port 80/TCP)
				policytypes.KeyForDirection(1).
					WithIdentity(202).
					WithPortProto(6, 80): policytypes.AllowEntry(),
				// 4. L3 Ingress Deny (All ports)
				policytypes.KeyForDirection(0).
					WithIdentity(204): policytypes.AllowEntry().WithDeny(true),
			}
			desiredPolicy.CopyMapStateFrom(m)
			ep.desiredPolicy = desiredPolicy

			// Also mock realizedPolicy to prevent panics during comparisons
			ep.realizedPolicy = policy.NewEndpointPolicy(slog.Default(), repo)

			desiredPolicy.SelectorPolicy.IngressPolicyEnabled = true
			desiredPolicy.SelectorPolicy.EgressPolicyEnabled = true
			if !enabled {
				ep.policyMap, err = policyMapFactory.OpenEndpoint(ep.ID)
				require.NoError(t, err)
				t.Cleanup(func() {
					require.NoError(t, ep.policyMap.Close())
					require.NoError(t, os.RemoveAll(bpf.LocalMapPath(logger, policymap.MapName, ep.ID)))
				})
			}

			// 2. Run syncPolicyMap!
			err = ep.syncPolicyMap()
			require.NoError(t, err)
			dump, err := ep.DumpPolicyMap()
			require.NoError(t, err)
			require.Len(t, dump, len(m))
			expectedEntries := make(map[policymap.PolicyKey]policymap.PolicyEntry)
			for key, entry := range m {
				bpfKey := policymap.NewKeyFromPolicyKey(key)
				expectedEntries[bpfKey] = policymap.NewEntryFromPolicyEntry(bpfKey, entry)
			}
			actualEntries := make(map[policymap.PolicyKey]policymap.PolicyEntry)
			for _, entry := range dump {
				actualEntries[entry.Key] = entry.PolicyEntry
			}
			require.Equal(t, expectedEntries, actualEntries)
			if !enabled {
				require.Equal(t, PolicyMapPressureEvent{
					EndpointID: ep.ID,
					Value:      float64(len(m)) / float64(ep.policyMap.MaxEntries()),
				}, pressure.event)

				// RemoveEndpoint removes the endpoint's policy map pin. The endpoint
				// was never added to the global policy call maps.
				require.ErrorIs(t, policyMapFactory.RemoveEndpoint(ep.ID), ebpf.ErrKeyNotExist)
				require.NoFileExists(t, bpf.LocalMapPath(logger, policymap.MapName, ep.ID))
				return
			}

			// 3. Verify that overlay map has ep 42 pointing to some rule set ID
			overlayKey := policymap.OverlayKey{EndpointID: 42}
			val, err := overlay.Lookup(&overlayKey)
			require.NoError(t, err)
			ruleSetID := val.(*policymap.OverlayValue).RuleSetID
			require.Positive(t, ruleSetID)

			// 4. Verify that shared policy map has the rules

			// Verify Case 1: L4 Egress Redirection
			sharedKey1 := policymap.SharedPolicyKey{
				Prefixlen:        policymap.SharedPolicyFullPrefix, // 96
				RuleSetID:        ruleSetID,
				Identity:         200,
				TrafficDirection: 1, // Egress
				Nexthdr:          6,
				DestPortNetwork:  byteorder.HostToNetwork16(443),
			}
			entry1, err := shared.Lookup(&sharedKey1)
			require.NoError(t, err)
			require.NotNil(t, entry1)
			require.Equal(t, uint16(15001), entry1.(*policymap.PolicyEntry).GetProxyPort())

			// Verify Case 2: L3 Egress Allow
			sharedKey2 := policymap.SharedPolicyKey{
				Prefixlen:        policymap.SharedPolicyBasePrefix, // 72
				RuleSetID:        ruleSetID,
				Identity:         201,
				TrafficDirection: 1, // Egress
				Nexthdr:          0,
				DestPortNetwork:  0,
			}
			entry2, err := shared.Lookup(&sharedKey2)
			require.NoError(t, err)
			require.NotNil(t, entry2)
			require.False(t, entry2.(*policymap.PolicyEntry).IsDeny())

			// Verify Case 3: L4 Egress Allow
			sharedKey3 := policymap.SharedPolicyKey{
				Prefixlen:        policymap.SharedPolicyFullPrefix, // 96
				RuleSetID:        ruleSetID,
				Identity:         202,
				TrafficDirection: 1, // Egress
				Nexthdr:          6,
				DestPortNetwork:  byteorder.HostToNetwork16(80),
			}
			entry3, err := shared.Lookup(&sharedKey3)
			require.NoError(t, err)
			require.NotNil(t, entry3)
			require.False(t, entry3.(*policymap.PolicyEntry).IsDeny())

			// Verify Case 4: L3 Ingress Deny
			sharedKey4 := policymap.SharedPolicyKey{
				Prefixlen:        policymap.SharedPolicyBasePrefix, // 72
				RuleSetID:        ruleSetID,
				Identity:         204,
				TrafficDirection: 0, // Ingress
				Nexthdr:          0,
				DestPortNetwork:  0,
			}
			entry4, err := shared.Lookup(&sharedKey4)
			require.NoError(t, err)
			require.NotNil(t, entry4)
			require.True(t, entry4.(*policymap.PolicyEntry).IsDeny())

			// 5. RemoveEndpoint removes the endpoint's overlay entry and its rule set,
			// which no other endpoint uses. The endpoint was never added to the global
			// policy call maps.
			require.ErrorIs(t, policyMapFactory.RemoveEndpoint(ep.ID), ebpf.ErrKeyNotExist)
			_, err = overlay.Lookup(&overlayKey)
			require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
			_, err = shared.Lookup(&sharedKey1)
			require.ErrorIs(t, err, ebpf.ErrKeyNotExist)
		})
	}
}

type policyMapPressureRecorder struct {
	event PolicyMapPressureEvent
}

func (p *policyMapPressureRecorder) Update(event PolicyMapPressureEvent) {
	p.event = event
}

func (*policyMapPressureRecorder) Remove(uint16) {}
