// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package infraendpoints

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containernetworking/cni/libcni"
	cnicoretypes "github.com/containernetworking/cni/pkg/types"
	cnitypesv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/daemon/cmd/cni/fake"
	"github.com/cilium/cilium/pkg/node"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"
)

// fakeDelegatedIPAMNetNS is a delegatedIPAMNetNS that doesn't touch the kernel. It lets
// unit tests exercise the delegated IPAM flow unprivileged.
type fakeDelegatedIPAMNetNS struct {
	path   string
	closed bool
}

func (f *fakeDelegatedIPAMNetNS) Path() string { return f.path }
func (f *fakeDelegatedIPAMNetNS) Close() error { f.closed = true; return nil }
func newFakeNetNS() *fakeDelegatedIPAMNetNS {
	return &fakeDelegatedIPAMNetNS{path: "/proc/self/fd/1234"}
}

// mockCNIExec implements cniInvoke.Exec for testing.
type mockCNIExec struct {
	version.PluginDecoder
	execResult []byte
	execErr    error
	findErr    error
	commands   []string
}

func (m *mockCNIExec) ExecPlugin(_ context.Context, _ string, _ []byte, env []string) ([]byte, error) {
	for _, kv := range env {
		if cmd, ok := strings.CutPrefix(kv, "CNI_COMMAND="); ok {
			m.commands = append(m.commands, cmd)
			break
		}
	}
	return m.execResult, m.execErr
}

func (m *mockCNIExec) FindInPath(plugin string, paths []string) (string, error) {
	if m.findErr != nil {
		return "", m.findErr
	}
	if len(paths) > 0 {
		return filepath.Join(paths[0], plugin), nil
	}
	return "", errors.New("no paths provided")
}

func TestNewDelegatedIPAMArgs(t *testing.T) {
	netns := newFakeNetNS()
	args := newDelegatedIPAMArgs("ADD", "cilium-ingress-node-a", "/opt/cni/bin", netns)
	require.Equal(t, "ADD", args.Command)
	require.Equal(t, "cilium-ingress-node-a", args.ContainerID)
	require.Equal(t, "/proc/self/fd/1234", args.NetNS)
	require.Equal(t, "eth0", args.IfName)
	require.Equal(t, "/opt/cni/bin", args.Path)
	require.Equal(t, [][2]string{
		{"IgnoreUnknown", "true"},
		{"K8S_POD_NAME", "cilium-ingress-node-a"},
		{"K8S_POD_NAMESPACE", "kube-system"},
	}, args.PluginArgs)

	delArgs := newDelegatedIPAMArgs("DEL", "cilium-ingress-node-a", "/opt/cni/bin", newFakeNetNS())
	require.Equal(t, "DEL", delArgs.Command)
	require.Equal(t, args.ContainerID, delArgs.ContainerID)
	require.Equal(t, args.IfName, delArgs.IfName)
}

func TestDelegatedIPAMContainerID(t *testing.T) {
	require.Equal(t, "cilium-ingress-node-a", delegatedIPAMContainerID("node-a"))
}

func TestDelegatedIPAMPluginConfig(t *testing.T) {
	tests := []struct {
		name      string
		netConf   *cnitypes.NetConf
		expectErr string
		expectOK  bool
	}{
		{
			name:      "nil netConf",
			netConf:   nil,
			expectErr: "no CNI configuration available",
		},
		{
			name:      "nil PluginConfig",
			netConf:   &cnitypes.NetConf{NetConf: cnicoretypes.NetConf{CNIVersion: "1.0.0", Name: "test"}},
			expectErr: "no plugin config",
		},
		{
			name: "PluginConfig with nil Network",
			netConf: &cnitypes.NetConf{
				NetConf:      cnicoretypes.NetConf{CNIVersion: "1.0.0", Name: "test"},
				PluginConfig: &libcni.PluginConfig{Network: nil, Bytes: []byte("{}")},
			},
			expectErr: "no parsed network section",
		},
		{
			name: "PluginConfig with empty Bytes",
			netConf: &cnitypes.NetConf{
				NetConf: cnicoretypes.NetConf{CNIVersion: "1.0.0", Name: "test"},
				PluginConfig: &libcni.PluginConfig{
					Network: &cnicoretypes.PluginConf{IPAM: cnicoretypes.IPAM{Type: "host-local"}},
					Bytes:   nil,
				},
			},
			expectErr: "no preserved raw bytes",
		},
		{
			name: "PluginConfig with empty IPAM type",
			netConf: &cnitypes.NetConf{
				NetConf: cnicoretypes.NetConf{CNIVersion: "1.0.0", Name: "test"},
				PluginConfig: &libcni.PluginConfig{
					Network: &cnicoretypes.PluginConf{},
					Bytes:   []byte(`{"cniVersion":"1.0.0","name":"test"}`),
				},
			},
			expectErr: "does not specify an IPAM type",
		},
		{
			name: "valid PluginConfig",
			netConf: &cnitypes.NetConf{
				NetConf: cnicoretypes.NetConf{CNIVersion: "1.0.0", Name: "test"},
				PluginConfig: &libcni.PluginConfig{
					Network: &cnicoretypes.PluginConf{IPAM: cnicoretypes.IPAM{Type: "host-local"}},
					Bytes:   []byte(`{"cniVersion":"1.0.0","name":"test","ipam":{"type":"host-local"}}`),
				},
			},
			expectOK: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &infraIPAllocator{
				cniConfigManager: &fake.FakeCNIConfigManager{CustomNetConf: tt.netConf},
			}
			pc, err := r.delegatedIPAMPluginConfig()
			if tt.expectOK {
				require.NoError(t, err)
				require.NotNil(t, pc)
				return
			}
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectErr)
		})
	}
}

func newTestAllocator(t *testing.T, netConf *cnitypes.NetConf, cniBinPath string, enableIPv4, enableIPv6 bool) *infraIPAllocator {
	t.Helper()
	// Seed PluginConfig with raw bytes so delegatedIPAMPluginConfig can forward
	// them to the plugin.
	if netConf != nil && netConf.PluginConfig == nil && netConf.IPAM.Type != "" {
		raw := fmt.Sprintf(
			`{"cniVersion":"%s","name":"%s","type":"cilium-cni","ipam":{"type":"%s"}}`,
			netConf.CNIVersion, netConf.Name, netConf.IPAM.Type,
		)
		pc, err := libcni.NetworkPluginConfFromBytes([]byte(raw))
		require.NoError(t, err)
		netConf.PluginConfig = pc
	}

	localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{Node: nodetypes.Node{Name: "node-a"}})
	return &infraIPAllocator{
		logger: slog.Default(),
		daemonConfig: &option.DaemonConfig{
			EnableIPv4: enableIPv4,
			EnableIPv6: enableIPv6,
		},
		localNodeStore: localNodeStore,
		cniConfigManager: &fake.FakeCNIConfigManager{
			CustomNetConf:           netConf,
			DelegatedIPAMCNIBinPath: cniBinPath,
		},
	}
}

func makeCNIResult(t testing.TB, ips ...string) []byte {
	t.Helper()
	result := &cnitypesv1.Result{
		CNIVersion: "1.0.0",
	}
	for _, ip := range ips {
		hostIP, ipNet, err := net.ParseCIDR(ip)
		require.NoError(t, err)
		// Use host IP, not network IP
		ipNet.IP = hostIP
		result.IPs = append(result.IPs, &cnitypesv1.IPConfig{
			Address: *ipNet,
		})
	}
	b, err := json.Marshal(result)
	require.NoError(t, err)
	return b
}

func TestAllocateIngressIPsWithDelegatedIPAM(t *testing.T) {
	tests := []struct {
		name           string
		netConf        *cnitypes.NetConf
		execIPs        []string
		withExecResult bool
		execErr        error
		enableIPv4     bool
		enableIPv6     bool
		expectErr      bool
		expectV4       string
		expectV6       string
	}{
		{
			name: "IPv4 allocation",
			netConf: &cnitypes.NetConf{
				NetConf: cnicoretypes.NetConf{
					CNIVersion: "1.0.0",
					Name:       "test",
					Type:       "cilium-cni",
				},
				IPAM: cnitypes.IPAM{
					IPAM: cnicoretypes.IPAM{Type: "host-local"},
				},
			},
			execIPs:        []string{"10.0.0.1/24"},
			withExecResult: true,
			enableIPv4:     true,
			enableIPv6:     false,
			expectV4:       "10.0.0.1",
		},
		{
			name: "IPv6 allocation",
			netConf: &cnitypes.NetConf{
				NetConf: cnicoretypes.NetConf{
					CNIVersion: "1.0.0",
					Name:       "test",
					Type:       "cilium-cni",
				},
				IPAM: cnitypes.IPAM{
					IPAM: cnicoretypes.IPAM{Type: "host-local"},
				},
			},
			execIPs:        []string{"fd00::1/128"},
			withExecResult: true,
			enableIPv4:     false,
			enableIPv6:     true,
			expectV6:       "fd00::1",
		},
		{
			name: "dual stack allocation",
			netConf: &cnitypes.NetConf{
				NetConf: cnicoretypes.NetConf{
					CNIVersion: "1.0.0",
					Name:       "test",
					Type:       "cilium-cni",
				},
				IPAM: cnitypes.IPAM{
					IPAM: cnicoretypes.IPAM{Type: "host-local"},
				},
			},
			execIPs:        []string{"10.0.0.1/24", "fd00::1/128"},
			withExecResult: true,
			enableIPv4:     true,
			enableIPv6:     true,
			expectV4:       "10.0.0.1",
			expectV6:       "fd00::1",
		},
		{
			name: "dual stack missing IPv6 fails",
			netConf: &cnitypes.NetConf{
				NetConf: cnicoretypes.NetConf{
					CNIVersion: "1.0.0",
					Name:       "test",
					Type:       "cilium-cni",
				},
				IPAM: cnitypes.IPAM{
					IPAM: cnicoretypes.IPAM{Type: "host-local"},
				},
			},
			execIPs:        []string{"10.0.0.1/24"},
			withExecResult: true,
			enableIPv4:     true,
			enableIPv6:     true,
			expectErr:      true,
		},
		{
			name: "dual stack missing IPv4 fails",
			netConf: &cnitypes.NetConf{
				NetConf: cnicoretypes.NetConf{
					CNIVersion: "1.0.0",
					Name:       "test",
					Type:       "cilium-cni",
				},
				IPAM: cnitypes.IPAM{
					IPAM: cnicoretypes.IPAM{Type: "host-local"},
				},
			},
			execIPs:        []string{"fd00::1/128"},
			withExecResult: true,
			enableIPv4:     true,
			enableIPv6:     true,
			expectErr:      true,
		},
		{
			name: "IPv4-only ignores IPv6 from plugin",
			netConf: &cnitypes.NetConf{
				NetConf: cnicoretypes.NetConf{
					CNIVersion: "1.0.0",
					Name:       "test",
					Type:       "cilium-cni",
				},
				IPAM: cnitypes.IPAM{
					IPAM: cnicoretypes.IPAM{Type: "host-local"},
				},
			},
			execIPs:        []string{"10.0.0.1/24", "fd00::1/128"},
			withExecResult: true,
			enableIPv4:     true,
			enableIPv6:     false,
			expectV4:       "10.0.0.1",
		},
		{
			name: "plugin exec error",
			netConf: &cnitypes.NetConf{
				NetConf: cnicoretypes.NetConf{
					CNIVersion: "1.0.0",
					Name:       "test",
					Type:       "cilium-cni",
				},
				IPAM: cnitypes.IPAM{
					IPAM: cnicoretypes.IPAM{Type: "host-local"},
				},
			},
			execErr:    errors.New("exec failed"),
			enableIPv4: true,
			enableIPv6: true,
			expectErr:  true,
		},
		{
			name:       "no CNI config",
			netConf:    nil,
			enableIPv4: true,
			enableIPv6: true,
			expectErr:  true,
		},
		{
			name: "no IPAM type",
			netConf: &cnitypes.NetConf{
				NetConf: cnicoretypes.NetConf{
					CNIVersion: "1.0.0",
					Name:       "test",
					Type:       "cilium-cni",
				},
			},
			enableIPv4: true,
			enableIPv6: true,
			expectErr:  true,
		},
		{
			name: "empty result",
			netConf: &cnitypes.NetConf{
				NetConf: cnicoretypes.NetConf{
					CNIVersion: "1.0.0",
					Name:       "test",
					Type:       "cilium-cni",
				},
				IPAM: cnitypes.IPAM{
					IPAM: cnicoretypes.IPAM{Type: "host-local"},
				},
			},
			withExecResult: true,
			enableIPv4:     true,
			enableIPv6:     true,
			expectErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec := &mockCNIExec{execErr: tt.execErr}
			if tt.withExecResult {
				exec.execResult = makeCNIResult(t, tt.execIPs...)
			}
			alloc := newTestAllocator(t, tt.netConf, "/opt/cni/bin", tt.enableIPv4, tt.enableIPv6)
			err := alloc.allocateIngressIPsWithDelegatedIPAMExecAndNetNS(context.Background(), exec, newFakeNetNS())
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
			} else {
				require.Nil(t, localNode.IPv4IngressIP)
			}
			if tt.expectV6 != "" {
				require.NotNil(t, localNode.IPv6IngressIP)
				require.Equal(t, tt.expectV6, localNode.IPv6IngressIP.String())
			} else {
				require.Nil(t, localNode.IPv6IngressIP)
			}
		})
	}
}

// TestAllocateIngressIPsDELOnError asserts that
// when an ADD succeeds at the plugin layer but allocation later fails due to a
// missing required family, an offsetting DEL is issued so the plugin's lease
// is not orphaned.
func TestAllocateIngressIPsDELOnError(t *testing.T) {
	netConf := &cnitypes.NetConf{
		NetConf: cnicoretypes.NetConf{CNIVersion: "1.0.0", Name: "test", Type: "cilium-cni"},
		IPAM:    cnitypes.IPAM{IPAM: cnicoretypes.IPAM{Type: "host-local"}},
	}
	exec := &mockCNIExec{
		// Plugin returns only IPv4 even though dual-stack is required. This
		// triggers the post-ADD validation error path.
		execResult: makeCNIResult(t, "10.0.0.1/24"),
	}
	alloc := newTestAllocator(t, netConf, "/opt/cni/bin", true, true)
	err := alloc.allocateIngressIPsWithDelegatedIPAMExecAndNetNS(context.Background(), exec, newFakeNetNS())
	require.Error(t, err)
	require.Equal(t, []string{"ADD", "DEL"}, exec.commands,
		"failed allocation must issue a compensating DEL to release the plugin lease")
}

func TestDeallocateIngressIPsWithDelegatedIPAM(t *testing.T) {
	validNetConf := func() *cnitypes.NetConf {
		return &cnitypes.NetConf{
			NetConf: cnicoretypes.NetConf{
				CNIVersion: "1.0.0",
				Name:       "test",
				Type:       "cilium-cni",
			},
			IPAM: cnitypes.IPAM{
				IPAM: cnicoretypes.IPAM{Type: "host-local"},
			},
		}
	}

	tests := []struct {
		name       string
		netConf    *cnitypes.NetConf
		cniBinPath string
		exec       *mockCNIExec
		// Pre-existing local-node ingress IPs at the time of deallocation.
		// Drives the per-family success log assertions.
		v4Ingress net.IP
		v6Ingress net.IP
		// Substrings expected in the returned error message.
		wantErrContains []string
		// Substrings expected in INFO log records.
		wantInfoContains []string
		// Substrings that must NOT appear in any log record.
		wantAbsent []string
	}{
		{
			name:             "dual-stack successful deallocation logs both families",
			netConf:          validNetConf(),
			cniBinPath:       "/opt/cni/bin",
			exec:             &mockCNIExec{execResult: []byte("{}")},
			v4Ingress:        net.ParseIP("10.0.0.1"),
			v6Ingress:        net.ParseIP("fd00::1"),
			wantInfoContains: []string{"Deallocated IPv4 ingress address", "Deallocated IPv6 ingress address"},
		},
		{
			name:             "single-stack IPv4 only logs IPv4",
			netConf:          validNetConf(),
			cniBinPath:       "/opt/cni/bin",
			exec:             &mockCNIExec{execResult: []byte("{}")},
			v4Ingress:        net.ParseIP("10.0.0.1"),
			wantInfoContains: []string{"Deallocated IPv4 ingress address"},
			wantAbsent:       []string{"Deallocated IPv6", "<nil>"},
		},
		{
			name:             "single-stack IPv6 only logs IPv6",
			netConf:          validNetConf(),
			cniBinPath:       "/opt/cni/bin",
			exec:             &mockCNIExec{execResult: []byte("{}")},
			v6Ingress:        net.ParseIP("fd00::1"),
			wantInfoContains: []string{"Deallocated IPv6 ingress address"},
			wantAbsent:       []string{"Deallocated IPv4", "<nil>"},
		},
		{
			name:            "no CNI config",
			netConf:         nil,
			cniBinPath:      "/opt/cni/bin",
			exec:            &mockCNIExec{},
			wantErrContains: []string{"no CNI configuration available"},
		},
		{
			// Both the conflist and the CNI bin path are unusable. The function
			// short-circuits at the conflist read, the bin path is never consulted.
			name:            "neither conflist nor CNI bin readable",
			netConf:         nil,
			cniBinPath:      "/does/not/exist",
			exec:            &mockCNIExec{findErr: errors.New("not found")},
			wantErrContains: []string{"no CNI configuration available"},
			wantAbsent:      []string{"Failed to find IPAM plugin"},
		},
		{
			name:            "plugin find error",
			netConf:         validNetConf(),
			cniBinPath:      "/opt/cni/bin",
			exec:            &mockCNIExec{findErr: errors.New("not found")},
			wantErrContains: []string{"failed to find IPAM plugin"},
		},
		{
			name:            "plugin exec error",
			netConf:         validNetConf(),
			cniBinPath:      "/opt/cni/bin",
			exec:            &mockCNIExec{execErr: errors.New("exec failed")},
			wantErrContains: []string{"failed to execute IPAM plugin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alloc := newTestAllocator(t, tt.netConf, tt.cniBinPath, true, true)
			alloc.localNodeStore.Update(func(n *node.LocalNode) {
				n.IPv4IngressIP = tt.v4Ingress
				n.IPv6IngressIP = tt.v6Ingress
			})

			var buf strings.Builder
			alloc.logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

			err := alloc.deallocateIngressIPsWithDelegatedIPAMExecAndNetNS(context.Background(), tt.exec, newFakeNetNS())

			out := buf.String()
			if len(tt.wantErrContains) > 0 {
				require.Error(t, err)
				for _, want := range tt.wantErrContains {
					require.Containsf(t, err.Error(), want, "expected error substring %q in: %v", want, err)
				}
			} else {
				require.NoError(t, err)
			}
			for _, want := range tt.wantInfoContains {
				require.Containsf(t, out, want, "expected INFO substring %q in logs:\n%s", want, out)
			}
			for _, absent := range tt.wantAbsent {
				require.NotContainsf(t, out, absent, "did not expect %q in logs:\n%s", absent, out)
			}
		})
	}
}
