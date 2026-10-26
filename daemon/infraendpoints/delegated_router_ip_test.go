// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package infraendpoints

import (
	"context"
	"errors"
	"testing"

	cnitypes "github.com/containernetworking/cni/pkg/types"
	cnitypesv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/stretchr/testify/require"

	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	cnitypesplugin "github.com/cilium/cilium/plugins/cilium-cni/types"
)

func TestNeedsDelegatedRouterIPs(t *testing.T) {
	for _, tt := range []struct {
		name               string
		ipam               string
		v4, v6             bool
		routerV4, routerV6 string
		want               bool
	}{
		{name: "not delegated", ipam: ipamOption.IPAMClusterPool, v4: true},
		{name: "delegated, no static v4", ipam: ipamOption.IPAMDelegatedPlugin, v4: true, want: true},
		{name: "delegated, static v4", ipam: ipamOption.IPAMDelegatedPlugin, v4: true, routerV4: "169.254.23.0"},
		{name: "delegated, static v4, no static v6", ipam: ipamOption.IPAMDelegatedPlugin, v4: true, v6: true, routerV4: "169.254.23.0", want: true},
		{name: "delegated, both static", ipam: ipamOption.IPAMDelegatedPlugin, v4: true, v6: true, routerV4: "169.254.23.0", routerV6: "fe80::"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			alloc := newTestAllocator(t, nil, "", tt.v4, tt.v6)
			alloc.daemonConfig.IPAM = tt.ipam
			alloc.daemonConfig.LocalRouterIPv4 = tt.routerV4
			alloc.daemonConfig.LocalRouterIPv6 = tt.routerV6
			require.Equal(t, tt.want, alloc.needsDelegatedRouterIPs())
		})
	}
}

func newRouterLeaseTestAllocator(t *testing.T, stateDir string, v4, v6 bool) *infraIPAllocator {
	t.Helper()
	netConf := &cnitypesplugin.NetConf{
		NetConf: cnitypes.NetConf{CNIVersion: "1.0.0", Name: "cilium", Type: "cilium-cni"},
		IPAM:    cnitypesplugin.IPAM{IPAM: cnitypes.IPAM{Type: "host-local"}},
	}
	alloc := newTestAllocator(t, netConf, "/host/opt/cni/bin", v4, v6)
	alloc.daemonConfig.IPAM = ipamOption.IPAMDelegatedPlugin
	alloc.daemonConfig.StateDir = stateDir
	return alloc
}

func TestAllocateRouterIPsWithDelegatedIPAM(t *testing.T) {
	for _, tt := range []struct {
		name           string
		v4, v6         bool
		result         []byte
		execErr        error
		wantV4, wantV6 string
		wantCommands   []string
		wantErr        bool
	}{
		{name: "ipv4", v4: true, result: makeCNIResult(t, "10.1.128.13/17"), wantV4: "10.1.128.13", wantCommands: []string{"DEL", "ADD"}},
		{name: "dual stack", v4: true, v6: true, result: makeCNIResult(t, "10.102.1.69/16", "fd00::5/64"), wantV4: "10.102.1.69", wantV6: "fd00::5", wantCommands: []string{"DEL", "ADD"}},
		// The lease is released again when it can't be used.
		{name: "missing ipv6", v4: true, v6: true, result: makeCNIResult(t, "10.1.128.13/17"), wantCommands: []string{"DEL", "ADD", "DEL"}, wantErr: true},
		{name: "plugin error", v4: true, execErr: errors.New("boom"), wantCommands: []string{"DEL", "ADD"}, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			alloc := newRouterLeaseTestAllocator(t, t.TempDir(), tt.v4, tt.v6)
			exec := &mockCNIExec{execResult: tt.result, execErr: tt.execErr}
			ns := newFakeNetNS()

			v4, v6, err := alloc.allocateRouterIPsWithDelegatedIPAMExecAndNetNS(context.Background(), exec, ns)
			require.True(t, ns.closed, "the ephemeral netns must be closed")
			require.Equal(t, tt.wantCommands, exec.commands)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.wantV4 != "" {
				require.Equal(t, tt.wantV4, v4.String())
			}
			if tt.wantV6 != "" {
				require.Equal(t, tt.wantV6, v6.String())
			}
		})
	}
}

// TestDelegatedIPAMRouterLeaseRestart checks that a restarted agent reuses the
// router IP lease of its previous run instead of adding it again: the CNI
// contract doesn't allow a second ADD for the same container ID and interface
// without a DEL, and e.g. host-local rejects it.
func TestDelegatedIPAMRouterLeaseRestart(t *testing.T) {
	lease := func(alloc *infraIPAllocator, result []byte) (string, string, []string, error) {
		exec := &mockCNIExec{execResult: result}
		v4, v6, err := alloc.allocateRouterIPsWithDelegatedIPAMExecAndNetNS(context.Background(), exec, newFakeNetNS())
		return v4.String(), v6.String(), exec.commands, err
	}

	t.Run("reuses the lease of the previous run", func(t *testing.T) {
		stateDir := t.TempDir()
		v4, _, commands, err := lease(newRouterLeaseTestAllocator(t, stateDir, true, false), makeCNIResult(t, "10.244.1.3/24"))
		require.NoError(t, err)
		require.Equal(t, "10.244.1.3", v4)
		require.Equal(t, []string{"DEL", "ADD"}, commands)

		v4, _, commands, err = lease(newRouterLeaseTestAllocator(t, stateDir, true, false), makeCNIResult(t, "10.244.1.9/24"))
		require.NoError(t, err)
		require.Equal(t, "10.244.1.3", v4, "the router IP must survive an agent restart")
		require.Empty(t, commands, "no CNI call for a lease of this boot")
	})

	t.Run("leases again when the previous lease misses an enabled family", func(t *testing.T) {
		stateDir := t.TempDir()
		_, _, _, err := lease(newRouterLeaseTestAllocator(t, stateDir, true, false), makeCNIResult(t, "10.244.1.3/24"))
		require.NoError(t, err)

		v4, v6, commands, err := lease(newRouterLeaseTestAllocator(t, stateDir, true, true), makeCNIResult(t, "10.244.1.3/24", "fd00::3/64"))
		require.NoError(t, err)
		require.Equal(t, "10.244.1.3", v4)
		require.Equal(t, "fd00::3", v6)
		require.Equal(t, []string{"DEL", "ADD"}, commands)
	})

	t.Run("ignores the lease of another container ID", func(t *testing.T) {
		stateDir := t.TempDir()
		alloc := newRouterLeaseTestAllocator(t, stateDir, true, false)
		result, err := cnitypesv1.NewResult(makeCNIResult(t, "10.244.1.3/24"))
		require.NoError(t, err)
		converted, err := cnitypesv1.NewResultFromResult(result)
		require.NoError(t, err)
		alloc.saveDelegatedIPAMRouterLease("cilium-router-other-node", converted)

		v4, _, commands, err := lease(alloc, makeCNIResult(t, "10.244.1.7/24"))
		require.NoError(t, err)
		require.Equal(t, "10.244.1.7", v4)
		require.Equal(t, []string{"DEL", "ADD"}, commands)
	})

	t.Run("without a state directory every run leases again", func(t *testing.T) {
		for range 2 {
			_, _, commands, err := lease(newRouterLeaseTestAllocator(t, "", true, false), makeCNIResult(t, "10.244.1.3/24"))
			require.NoError(t, err)
			require.Equal(t, []string{"DEL", "ADD"}, commands)
		}
	})
}

func TestDelegatedIPAMRouterContainerID(t *testing.T) {
	require.Equal(t, "cilium-router-node-a", delegatedIPAMRouterContainerID("node-a"))
}
