// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"log/slog"
	"os"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/testutils"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

func setupSharedMapsPrivileged(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)
	bpf.CheckOrMountFS(logger, "")
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	_ = os.Remove(bpf.MapPath(logger, policymap.SharedPolicyMapName))
	_ = os.Remove(bpf.MapPath(logger, policymap.PolicyOverlayMapName))

	err := policymap.SharedPolicyMap.OpenOrCreate()
	require.NoError(t, err)
	err = policymap.PolicyOverlayMap.OpenOrCreate()
	require.NoError(t, err)
}

func TestPrivilegedEndpointPolicySyncShared(t *testing.T) {
	setupSharedMapsPrivileged(t)
	defer func() {
		policymap.SharedPolicyMap.Close()
		policymap.PolicyOverlayMap.Close()
	}()

	// 1. Enable Shared Policy Option
	option.Config.EnableSharedPolicy = true
	defer func() {
		option.Config.EnableSharedPolicy = false
	}()

	logger := hivetest.Logger(t)
	repo := policy.NewPolicyRepository(logger, nil, nil, nil, nil, testpolicy.NewPolicyMetricsNoop())

	// Create endpoint
	ep := &Endpoint{
		ID: 42,
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

	// 2. Run syncPolicyMap!
	err := ep.syncPolicyMap()
	require.NoError(t, err)

	// 3. Verify that overlay map has ep 42 pointing to some rule set ID
	overlayKey := policymap.OverlayKey{EndpointID: 42}
	val, err := policymap.PolicyOverlayMap.Lookup(&overlayKey)
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
		DestPortNetwork:  0xbb01, // 443
	}
	entry1, err := policymap.SharedPolicyMap.Lookup(&sharedKey1)
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
	entry2, err := policymap.SharedPolicyMap.Lookup(&sharedKey2)
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
		DestPortNetwork:  0x5000, // 80 in network byte order (80 = 0x0050 -> 0x5000)
	}
	entry3, err := policymap.SharedPolicyMap.Lookup(&sharedKey3)
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
	entry4, err := policymap.SharedPolicyMap.Lookup(&sharedKey4)
	require.NoError(t, err)
	require.NotNil(t, entry4)
	require.True(t, entry4.(*policymap.PolicyEntry).IsDeny())
}
