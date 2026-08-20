// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/maps/callsmap"
)

func TestStaleNetdevs(t *testing.T) {
	tests := map[string]struct {
		previous []*tables.Device
		current  []*tables.Device
		expected []*tables.Device
	}{
		"first observation": {
			current: []*tables.Device{{Name: "eth0", Index: 10}},
		},
		"addition": {
			previous: []*tables.Device{{Name: "eth0", Index: 10}},
			current:  []*tables.Device{{Name: "eth0", Index: 10}, {Name: "eth1", Index: 11}},
		},
		"removal": {
			previous: []*tables.Device{{Name: "eth0", Index: 10}, {Name: "eth1", Index: 11}},
			current:  []*tables.Device{{Name: "eth0", Index: 10}},
			expected: []*tables.Device{{Name: "eth1", Index: 11}},
		},
		"recreation": {
			previous: []*tables.Device{{Name: "eth0", Index: 10}},
			current:  []*tables.Device{{Name: "eth0", Index: 20}},
			expected: []*tables.Device{{Name: "eth0", Index: 10}},
		},
		"rename": {
			previous: []*tables.Device{{Name: "eth0", Index: 10}},
			current:  []*tables.Device{{Name: "renamed0", Index: 10}},
			expected: []*tables.Device{{Name: "eth0", Index: 10}},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			require.ElementsMatch(t, tt.expected, staleNetdevs(tt.previous, tt.current))
		})
	}
}

func TestCleanupChangedNetdevs(t *testing.T) {
	l := &loader{logger: hivetest.Logger(t)}

	initial := []*tables.Device{{Name: "eth0", Index: 10}}
	recreated := []*tables.Device{{Name: "eth0", Index: 20}, {Name: "eth1", Index: 21}}
	cleanupErr := errors.New("cleanup failed")
	var cleaned []*tables.Device
	err := l.cleanupChangedNetdevsWithCleanup(initial, recreated, func(stale *tables.Device) error {
		cleaned = append(cleaned, stale)
		return cleanupErr
	})
	require.ErrorIs(t, err, cleanupErr)
	require.Equal(t, initial, cleaned)

	// The orchestrator retains the previous configuration when reinitialization
	// fails, so retrying with the same inputs retries the same cleanup.
	cleaned = nil
	require.NoError(t, l.cleanupChangedNetdevsWithCleanup(initial, recreated, func(stale *tables.Device) error {
		cleaned = append(cleaned, stale)
		return nil
	}))
	require.Equal(t, initial, cleaned)
}

func TestRemoveStaleNetdevPins(t *testing.T) {
	bpffsBase := t.TempDir()
	mapsDir := t.TempDir()
	deviceName := "eth0.100"
	oldIfindex := 10

	deviceDir := bpffsDeviceNameDir(bpffsBase, deviceName)
	linksDir := filepath.Join(deviceDir, "links")
	pluginDir := filepath.Join(deviceDir, "plugins", "tc")
	require.NoError(t, os.MkdirAll(linksDir, 0o755))
	require.NoError(t, os.MkdirAll(pluginDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(linksDir, symbolFromHostNetdevEp), nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(pluginDir, "hook"), nil, 0o600))

	oldCallsMap := filepath.Join(mapsDir, bpf.LocalMapName(callsmap.NetdevMapName, uint16(oldIfindex)))
	currentCallsMap := filepath.Join(mapsDir, bpf.LocalMapName(callsmap.NetdevMapName, 20))
	require.NoError(t, os.WriteFile(oldCallsMap, nil, 0o600))
	require.NoError(t, os.WriteFile(currentCallsMap, nil, 0o600))

	require.NoError(t, removeStaleNetdevPins(bpffsBase, mapsDir, deviceName, oldIfindex))
	require.NoDirExists(t, deviceDir)
	require.NoFileExists(t, oldCallsMap)
	require.FileExists(t, currentCallsMap)

	// Cleanup is retried after errors, so it must be idempotent.
	require.NoError(t, removeStaleNetdevPins(bpffsBase, mapsDir, deviceName, oldIfindex))
}

func TestBPFMasqAddrs(t *testing.T) {
	masq4, masq6 := bpfMasqAddrs("test", &localNodeConfig, true, true)
	require.False(t, masq4.IsValid())
	require.False(t, masq6.IsValid())

	newConfig := localNodeConfig
	newConfig.NodeAddresses = []tables.NodeAddress{
		{
			Addr:       netip.MustParseAddr("1.0.0.1"),
			NodePort:   true,
			Primary:    true,
			DeviceName: "test",
		},
		{
			Addr:       netip.MustParseAddr("1000::1"),
			NodePort:   true,
			Primary:    true,
			DeviceName: "test",
		},
		{
			Addr:       netip.MustParseAddr("2.0.0.2"),
			NodePort:   false,
			Primary:    true,
			DeviceName: tables.WildcardDeviceName,
		},
		{
			Addr:       netip.MustParseAddr("2000::2"),
			NodePort:   false,
			Primary:    true,
			DeviceName: tables.WildcardDeviceName,
		},
	}

	masq4, masq6 = bpfMasqAddrs("test", &newConfig, true, true)
	require.Equal(t, "1.0.0.1", masq4.String())
	require.Equal(t, "1000::1", masq6.String())

	masq4, masq6 = bpfMasqAddrs("unknown", &newConfig, true, true)
	require.Equal(t, "2.0.0.2", masq4.String())
	require.Equal(t, "2000::2", masq6.String())

	masq4, masq6 = bpfMasqAddrs("test", &newConfig, false, false)
	require.False(t, masq4.IsValid())
	require.False(t, masq6.IsValid())
}
