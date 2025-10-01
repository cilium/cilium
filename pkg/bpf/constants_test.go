// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/config"
)

func TestPrintConstants(t *testing.T) {
	consts := []any{
		struct{ Foo int }{Foo: 42},
		map[string]any{"baz": true},
		uint32(123),
	}
	assert.Equal(t, "[]", printConstants(nil))
	assert.Equal(t, `["foo"]`, printConstants([]any{nil, "foo"}))
	assert.Equal(t, "[]", printConstants([]int{}))
	assert.Equal(t, "[]", printConstants([]any{}))
	assert.Equal(t, "[]", printConstants([]any{nil, nil}))
	assert.Equal(t, `[42]`, printConstants(42))
	assert.Equal(t, `[42, "foo"]`, printConstants([]any{42, "foo"}))

	assert.Equal(t, `[struct { Foo int }{Foo:42}, map[string]interface {}{"baz":true}, 0x7b]`, printConstants(consts))
}

func TestDumpConstants(t *testing.T) {
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

	type testObj struct {
		DeviceMTU uint16 `config:"device_mtu"`
		EnableFoo bool   `config:"enable_foo"`
	}
	constants := &testObj{
		DeviceMTU: 1500,
		EnableFoo: true,
	}

	opts := &CollectionOptions{
		ConfigDumpPath: configPath,
		Constants:      constants,
	}

	err := dumpConstants(spec, opts)
	require.NoError(t, err)

	data, err := os.ReadFile(configPath)
	require.NoError(t, err)

	var result configDumpLayout
	err = json.Unmarshal(data, &result)
	require.NoError(t, err)

	// Verify the objects section. This is mainly for human consumption, but we
	// check that it at least contains the expected values.
	assert.Len(t, result.Objects, 1)
	obj := result.Objects[0]
	assert.Contains(t, obj.Name, "bpf.testObj")

	v := obj.Values.(map[string]any)
	assert.Equal(t, float64(1500), v["DeviceMTU"])
	assert.Equal(t, true, v["EnableFoo"])

	// Verify the variables section contains only config section variables.
	assert.Len(t, result.Variables, 2)
	assert.Equal(t, []byte{0xdc, 0x05}, result.Variables["__config_device_mtu"])
	assert.Equal(t, []byte{0x01}, result.Variables["__config_enable_foo"])
	assert.NotContains(t, result.Variables, "other_var")
}
