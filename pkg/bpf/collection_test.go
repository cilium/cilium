// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPrivilegedUpgradeMap(t *testing.T) {
	testutils.PrivilegedTest(t)
	logger := hivetest.Logger(t)

	temp := testutils.TempBPFFS(t)

	// Pin a dummy map in order to test upgrading it.
	_, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Name:       "upgraded_map",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		Pinning:    ebpf.PinByName,
	}, ebpf.MapOptions{PinPath: temp})
	require.NoError(t, err)

	spec, err := ebpf.LoadCollectionSpec("testdata/upgrade-map.o")
	require.NoError(t, err)

	// Use LoadAndAssign to make sure commit works through map upgrades. This is a
	// regression test, as [ebpf.Collection.Assign] deletes Map objects from the
	// Collection when successful, causing commit() to fail afterwards if it uses
	// stringly references to Collection.Maps entries.
	obj := struct {
		UpgradedMap *ebpf.Map `ebpf:"upgraded_map"`
	}{}
	commit, err := LoadAndAssign(logger, &obj, spec, &CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: temp},
		},
	})
	require.NoError(t, err)
	require.NoError(t, commit())

	// Check if the map was upgraded correctly.
	assert.True(t, obj.UpgradedMap.IsPinned())
	assert.EqualValues(t, 10, obj.UpgradedMap.MaxEntries())
}

func TestSerializeConstants(t *testing.T) {
	logger := hivetest.Logger(t)
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")

	spec := &ebpf.CollectionSpec{
		Variables: map[string]*ebpf.VariableSpec{
			"__config_device_mtu": {
				Name:        "__config_device_mtu",
				SectionName: config.Section,
				Value:       []byte{0xdc, 0x05}, // 1500
			},
			"__config_enable_foo": {
				Name:        "__config_enable_foo",
				SectionName: config.Section,
				Value:       []byte{0x01}, // true
			},
			// Variable in a different section should be excluded.
			"other_var": {
				Name:        "other_var",
				SectionName: ".rodata",
				Value:       []byte{0xff},
			},
		},
	}

	type testConfig struct {
		DeviceMTU uint16 `config:"device_mtu"`
		EnableFoo bool   `config:"enable_foo"`
	}
	constants := &testConfig{
		DeviceMTU: 1500,
		EnableFoo: true,
	}

	opts := &CollectionOptions{
		ConfigPath: configPath,
		Constants:  constants,
	}

	err := serializeConstants(logger, spec, opts)
	require.NoError(t, err)

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)

	var result struct {
		Object    testConfig        `json:"object"`
		Variables map[string][]byte `json:"variables"`
	}
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Verify the object section.
	assert.Equal(t, uint16(1500), result.Object.DeviceMTU)
	assert.True(t, result.Object.EnableFoo)

	// Verify the variables section contains only config section variables.
	assert.Len(t, result.Variables, 2)
	assert.Equal(t, []byte{0xdc, 0x05}, result.Variables["__config_device_mtu"])
	assert.Equal(t, []byte{0x01}, result.Variables["__config_enable_foo"])
	assert.NotContains(t, result.Variables, "other_var")
}
