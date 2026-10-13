// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/vtep"
	"github.com/cilium/cilium/pkg/mountinfo"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/types"
)

func TestPrivilegedVTEPCommands(t *testing.T) {
	testutils.PrivilegedTest(t)

	const childEnv = "CILIUM_VTEP_TEST_CHILD"
	if os.Getenv(childEnv) == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestPrivilegedVTEPCommands$", "-test.v")
		// cmd.test would initialize the subprocess as cilium-agent instead of cilium-dbg.
		cmd.Args[0] = "cilium-dbg-vtep-test"
		cmd.Env = append(os.Environ(), childEnv+"=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: unix.CLONE_NEWNS}
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", output)
		return
	}

	require.NoError(t, unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""))
	runDir := t.TempDir()
	// Keep the default-path fixture separate from the host's runtime state.
	require.NoError(t, unix.Mount(runDir, filepath.Dir(defaults.RuntimePath), "", unix.MS_BIND, ""))
	mounts, err := mountinfo.GetMountInfo()
	require.NoError(t, err)
	bpfRoot := defaults.BPFFSRoot
	for _, mount := range mounts {
		if mount.FilesystemType == "bpf" {
			bpfRoot = mount.MountPoint
			break
		}
	}
	require.NoError(t, os.MkdirAll(bpfRoot, 0755))
	require.NoError(t, unix.Mount("bpf", bpfRoot, "bpf", 0, ""))
	require.NoError(t, os.MkdirAll(filepath.Join(bpfRoot, defaults.TCGlobalsPath), 0755))

	vtepMap := bpf.NewMap(vtep.MapName, ebpf.Hash, &vtep.Key{}, &vtep.VtepEndpointInfo{},
		vtep.MaxEntries, unix.BPF_F_RDONLY_PROG)
	require.NoError(t, vtepMap.OpenOrCreate())
	t.Cleanup(func() {
		require.NoError(t, vtepMap.Close())
	})

	configFile := filepath.Join(defaults.RuntimePath, defaults.StateDir, "agent-runtime-config.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(configFile), 0755))
	require.NoError(t, os.WriteFile(configFile, []byte(`{"VtepCidrMask":"255.255.0.0"}`), 0600))
	cliConfigFile := filepath.Join(runDir, "cilium.yaml")
	require.NoError(t, os.WriteFile(cliConfigFile, nil, 0600))

	run := func(args ...string) {
		t.Helper()
		option.Config.VtepCidrMask = netip.Addr{}
		RootCmd.SetArgs(append([]string{"--config", cliConfigFile}, args...))
		require.NoError(t, RootCmd.Execute())
	}
	key := &vtep.Key{IP: types.IPv4{10, 1, 0, 0}}
	assertEntry := func(endpoint types.IPv4, macAddress string) {
		t.Helper()
		value, err := vtepMap.Lookup(key)
		require.NoError(t, err)
		expectedMAC, err := mac.ParseMAC(macAddress)
		require.NoError(t, err)
		require.Equal(t, &vtep.VtepEndpointInfo{
			VtepMAC:        expectedMAC,
			TunnelEndpoint: endpoint,
		}, value)
		require.Equal(t, "255.255.0.0", option.Config.VtepCidrMask.String())
	}

	run("bpf", "vtep", "add", "10.1.5.0/24", "10.169.72.236", "82:36:4c:98:2e:56")
	assertEntry(types.IPv4{10, 169, 72, 236}, "82:36:4c:98:2e:56")

	run("bpf", "vtep", "update", "10.1.5.0/24", "10.169.72.237", "82:36:4c:98:2e:57")
	assertEntry(types.IPv4{10, 169, 72, 237}, "82:36:4c:98:2e:57")

	run("bpf", "vtep", "delete", "10.1.5.0/24")
	_, err = vtepMap.Lookup(key)
	require.ErrorIs(t, err, ebpf.ErrKeyNotExist)

	require.NoError(t, os.Remove(configFile))
	run("bpf", "vtep", "list")
}
