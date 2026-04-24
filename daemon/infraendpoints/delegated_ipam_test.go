// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package infraendpoints

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"testing"

	"github.com/containernetworking/cni/libcni"
	cniCoreTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesV1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/daemon/cmd/cni/fake"
	"github.com/cilium/cilium/pkg/node"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"
)

// mockCNIExec implements cniInvoke.Exec for testing.
type mockCNIExec struct {
	version.PluginDecoder
	execResult []byte
	execErr    error
	findErr    error
}

func (m *mockCNIExec) ExecPlugin(_ context.Context, _ string, _ []byte, _ []string) ([]byte, error) {
	return m.execResult, m.execErr
}

func (m *mockCNIExec) FindInPath(plugin string, paths []string) (string, error) {
	if m.findErr != nil {
		return "", m.findErr
	}
	if len(paths) > 0 {
		return filepath.Join(paths[0], plugin), nil
	}
	return "", fmt.Errorf("no paths provided")
}

func TestNewDelegatedIPAMArgs(t *testing.T) {
	args := newDelegatedIPAMArgs("ADD", "cilium-ingress-node-a", "/opt/cni/bin")
	require.Equal(t, "ADD", args.Command)
	require.Equal(t, "cilium-ingress-node-a", args.ContainerID)
	require.Equal(t, "/proc/1/ns/net", args.NetNS)
	require.Equal(t, "eth0", args.IfName)
	require.Equal(t, "/opt/cni/bin", args.Path)
	require.Equal(t, [][2]string{
		{"IgnoreUnknown", "true"},
		{"K8S_POD_NAME", "cilium-ingress-node-a"},
		{"K8S_POD_NAMESPACE", "kube-system"},
	}, args.PluginArgs)

	delArgs := newDelegatedIPAMArgs("DEL", "cilium-ingress-node-a", "/opt/cni/bin")
	require.Equal(t, "DEL", delArgs.Command)
	// ADD and DEL must produce identical bookkeeping keys (containerID + ifname),
	// otherwise IPAM plugins (e.g. host-local) won't release what was allocated.
	require.Equal(t, args.ContainerID, delArgs.ContainerID)
	require.Equal(t, args.IfName, delArgs.IfName)
	require.Equal(t, args.NetNS, delArgs.NetNS)
}

func TestDelegatedIPAMContainerID(t *testing.T) {
	require.Equal(t, "cilium-ingress-node-a", delegatedIPAMContainerID("node-a"))
}

func TestDelegatedIPAMArgsAsEnv(t *testing.T) {
	args := newDelegatedIPAMArgs("ADD", "cilium-ingress-node-a", "/opt/cni/bin")
	env := args.AsEnv()

	found := false
	for _, e := range env {
		if e == "CNI_NETNS_OVERRIDE=1" {
			found = true
			break
		}
	}
	require.True(t, found, "CNI_NETNS_OVERRIDE=1 should be in environment")
}

func newTestAllocator(t *testing.T, netConf *cnitypes.NetConf, cniBinDir string) *infraIPAllocator {
	t.Helper()
	// Seed PluginConfig with a libcni view of a minimal plugin block matching
	// the typed IPAM type, so getDelegatedIPAMPluginConfig has bytes to forward
	// to the plugin. Tests that exercise the "no CNI config" surface pass
	// netConf=nil and skip this.
	if netConf != nil && netConf.PluginConfig == nil && netConf.IPAM.Type != "" {
		raw := fmt.Sprintf(
			`{"cniVersion":"%s","name":"%s","type":"cilium-cni","ipam":{"type":"%s"}}`,
			netConf.CNIVersion, netConf.Name, netConf.IPAM.Type,
		)
		pc, err := libcni.NetworkPluginConfFromBytes([]byte(raw))
		require.NoError(t, err)
		netConf.PluginConfig = pc
	}

	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{Node: nodeTypes.Node{Name: "node-a"}})
	return &infraIPAllocator{
		logger: slog.Default(),
		daemonConfig: &option.DaemonConfig{
			EnableIPv4: true,
			EnableIPv6: true,
		},
		localNodeStore: localNodeStore,
		cniConfigManager: &fake.FakeCNIConfigManager{
			CustomNetConf:          netConf,
			DelegatedIPAMCNIBinDir: cniBinDir,
		},
	}
}

func makeCNIResult(ips ...string) []byte {
	result := &cniTypesV1.Result{
		CNIVersion: "1.0.0",
	}
	for _, ip := range ips {
		hostIP, ipNet, err := net.ParseCIDR(ip)
		if err != nil {
			panic(err)
		}
		// Use host IP, not network IP
		ipNet.IP = hostIP
		result.IPs = append(result.IPs, &cniTypesV1.IPConfig{
			Address: *ipNet,
		})
	}
	b, _ := json.Marshal(result)
	return b
}

func TestAllocateIngressIPsWithDelegatedIPAM(t *testing.T) {
	tests := []struct {
		name      string
		netConf   *cnitypes.NetConf
		exec      *mockCNIExec
		expectErr bool
		expectV4  string
		expectV6  string
	}{
		{
			name: "IPv4 allocation",
			netConf: &cnitypes.NetConf{
				NetConf: cniCoreTypes.NetConf{
					CNIVersion: "1.0.0",
					Name:       "test",
					Type:       "cilium-cni",
				},
				IPAM: cnitypes.IPAM{
					IPAM: cniCoreTypes.IPAM{Type: "host-local"},
				},
			},
			exec: &mockCNIExec{
				execResult: makeCNIResult("10.0.0.1/24"),
			},
			expectV4: "10.0.0.1",
		},
		{
			name: "IPv6 allocation",
			netConf: &cnitypes.NetConf{
				NetConf: cniCoreTypes.NetConf{
					CNIVersion: "1.0.0",
					Name:       "test",
					Type:       "cilium-cni",
				},
				IPAM: cnitypes.IPAM{
					IPAM: cniCoreTypes.IPAM{Type: "host-local"},
				},
			},
			exec: &mockCNIExec{
				execResult: makeCNIResult("fd00::1/128"),
			},
			expectV6: "fd00::1",
		},
		{
			name: "dual stack allocation",
			netConf: &cnitypes.NetConf{
				NetConf: cniCoreTypes.NetConf{
					CNIVersion: "1.0.0",
					Name:       "test",
					Type:       "cilium-cni",
				},
				IPAM: cnitypes.IPAM{
					IPAM: cniCoreTypes.IPAM{Type: "host-local"},
				},
			},
			exec: &mockCNIExec{
				execResult: makeCNIResult("10.0.0.1/24", "fd00::1/128"),
			},
			expectV4: "10.0.0.1",
			expectV6: "fd00::1",
		},
		{
			name: "plugin exec error",
			netConf: &cnitypes.NetConf{
				NetConf: cniCoreTypes.NetConf{
					CNIVersion: "1.0.0",
					Name:       "test",
					Type:       "cilium-cni",
				},
				IPAM: cnitypes.IPAM{
					IPAM: cniCoreTypes.IPAM{Type: "host-local"},
				},
			},
			exec: &mockCNIExec{
				execErr: fmt.Errorf("exec failed"),
			},
			expectErr: true,
		},
		{
			name:      "no CNI config",
			netConf:   nil,
			exec:      &mockCNIExec{},
			expectErr: true,
		},
		{
			name: "no IPAM type",
			netConf: &cnitypes.NetConf{
				NetConf: cniCoreTypes.NetConf{
					CNIVersion: "1.0.0",
					Name:       "test",
					Type:       "cilium-cni",
				},
			},
			exec:      &mockCNIExec{},
			expectErr: true,
		},
		{
			name: "empty result",
			netConf: &cnitypes.NetConf{
				NetConf: cniCoreTypes.NetConf{
					CNIVersion: "1.0.0",
					Name:       "test",
					Type:       "cilium-cni",
				},
				IPAM: cnitypes.IPAM{
					IPAM: cniCoreTypes.IPAM{Type: "host-local"},
				},
			},
			exec: &mockCNIExec{
				execResult: makeCNIResult(),
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alloc := newTestAllocator(t, tt.netConf, "/opt/cni/bin")
			err := alloc.allocateIngressIPsWithDelegatedIPAMExec(context.Background(), tt.exec)
			if tt.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			ctx := context.Background()
			localNode, err := alloc.localNodeStore.Get(ctx)
			require.NoError(t, err)

			if tt.expectV4 != "" {
				require.NotNil(t, localNode.IPv4IngressIP)
				require.Equal(t, tt.expectV4, localNode.IPv4IngressIP.String())
			}
			if tt.expectV6 != "" {
				require.NotNil(t, localNode.IPv6IngressIP)
				require.Equal(t, tt.expectV6, localNode.IPv6IngressIP.String())
			}
		})
	}
}

func TestDeallocateIngressIPsWithDelegatedIPAM(t *testing.T) {
	tests := []struct {
		name    string
		netConf *cnitypes.NetConf
		exec    *mockCNIExec
	}{
		{
			name: "successful deallocation",
			netConf: &cnitypes.NetConf{
				NetConf: cniCoreTypes.NetConf{
					CNIVersion: "1.0.0",
					Name:       "test",
					Type:       "cilium-cni",
				},
				IPAM: cnitypes.IPAM{
					IPAM: cniCoreTypes.IPAM{Type: "host-local"},
				},
			},
			exec: &mockCNIExec{
				execResult: []byte("{}"),
			},
		},
		{
			name:    "no CNI config - logs warning",
			netConf: nil,
			exec:    &mockCNIExec{},
		},
		{
			name: "plugin find error - logs warning",
			netConf: &cnitypes.NetConf{
				NetConf: cniCoreTypes.NetConf{
					CNIVersion: "1.0.0",
					Name:       "test",
					Type:       "cilium-cni",
				},
				IPAM: cnitypes.IPAM{
					IPAM: cniCoreTypes.IPAM{Type: "host-local"},
				},
			},
			exec: &mockCNIExec{
				findErr: fmt.Errorf("not found"),
			},
		},
		{
			name: "plugin exec error - logs warning",
			netConf: &cnitypes.NetConf{
				NetConf: cniCoreTypes.NetConf{
					CNIVersion: "1.0.0",
					Name:       "test",
					Type:       "cilium-cni",
				},
				IPAM: cnitypes.IPAM{
					IPAM: cniCoreTypes.IPAM{Type: "host-local"},
				},
			},
			exec: &mockCNIExec{
				execErr: fmt.Errorf("exec failed"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alloc := newTestAllocator(t, tt.netConf, "/opt/cni/bin")
			// Should not panic
			alloc.deallocateIngressIPsWithDelegatedIPAMExec(context.Background(), tt.exec)
		})
	}
}
