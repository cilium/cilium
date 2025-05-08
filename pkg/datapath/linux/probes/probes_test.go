// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestSystemConfigProbes(t *testing.T) {
	testCases := []struct {
		systemConfig SystemConfig
		expectErr    bool
	}{
		{
			systemConfig: SystemConfig{
				ConfigCgroupBpf:   "y",
				ConfigLwtunnelBpf: "y",
				ConfigBpfEvents:   "y",
			},
			expectErr: false,
		},
		{
			systemConfig: SystemConfig{
				ConfigCgroupBpf:   "y",
				ConfigLwtunnelBpf: "y",
				ConfigBpfEvents:   "y",
			},
			expectErr: false,
		},
		// Disable options which generate errors
		{
			systemConfig: SystemConfig{
				ConfigCgroupBpf:   "n",
				ConfigLwtunnelBpf: "n",
				ConfigBpfEvents:   "n",
			},
			expectErr: true,
		},
		{
			systemConfig: SystemConfig{
				ConfigCgroupBpf:   "y",
				ConfigLwtunnelBpf: "y",
				ConfigBpfEvents:   "y",
			},
			expectErr: true,
		},
		{
			systemConfig: SystemConfig{
				ConfigCgroupBpf:   "y",
				ConfigLwtunnelBpf: "y",
				ConfigBpfEvents:   "y",
			},
			expectErr: true,
		},
		{
			systemConfig: SystemConfig{
				ConfigCgroupBpf:   "y",
				ConfigLwtunnelBpf: "y",
				ConfigBpfEvents:   "y",
			},
			expectErr: true,
		},
		{
			systemConfig: SystemConfig{
				ConfigCgroupBpf:   "y",
				ConfigLwtunnelBpf: "y",
				ConfigBpfEvents:   "y",
			},
			expectErr: true,
		},
		{
			systemConfig: SystemConfig{
				ConfigCgroupBpf:   "y",
				ConfigLwtunnelBpf: "y",
				ConfigBpfEvents:   "y",
			},
			expectErr: true,
		},
		{
			systemConfig: SystemConfig{
				ConfigCgroupBpf:   "y",
				ConfigLwtunnelBpf: "y",
				ConfigBpfEvents:   "y",
			},
			expectErr: true,
		},
		{
			systemConfig: SystemConfig{
				ConfigCgroupBpf:   "y",
				ConfigLwtunnelBpf: "y",
				ConfigBpfEvents:   "y",
			},
			expectErr: true,
		},
		// Disable options which generate warnings
		{
			systemConfig: SystemConfig{
				ConfigCgroupBpf:   "n",
				ConfigLwtunnelBpf: "n",
				ConfigBpfEvents:   "n",
			},
			expectErr: false,
		},
		{
			systemConfig: SystemConfig{
				ConfigCgroupBpf:   "n",
				ConfigLwtunnelBpf: "y",
				ConfigBpfEvents:   "y",
			},
			expectErr: false,
		},
		{
			systemConfig: SystemConfig{
				ConfigCgroupBpf:   "y",
				ConfigLwtunnelBpf: "n",
				ConfigBpfEvents:   "y",
			},
			expectErr: false,
		},
		{
			systemConfig: SystemConfig{
				ConfigCgroupBpf:   "y",
				ConfigLwtunnelBpf: "y",
				ConfigBpfEvents:   "n",
			},
			expectErr: false,
		},
	}
	for _, tc := range testCases {
		manager := &ProbeManager{
			logger:   hivetest.Logger(t),
			features: Features{SystemConfig: tc.systemConfig},
		}
		err := manager.SystemConfigProbes()
		if tc.expectErr {
			if err == nil {
				t.Error("unexpected nil error")
			}
		} else {
			if err != nil {
				t.Error(err)
			}
		}
	}
}

func TestWriteFeatureHeader(t *testing.T) {
	testCases := []struct {
		features      map[string]bool
		common        bool
		expectedLines []string
	}{
		{
			features: map[string]bool{
				"HAVE_FEATURE_MACRO": true,
			},
			common: true,
			expectedLines: []string{
				"#define HAVE_FEATURE_MACRO 1",
			},
		},
		{
			features: map[string]bool{
				"HAVE_FEATURE_MACRO": true,
			},
			common: false,
			expectedLines: []string{
				"#include \"features.h\"",
				"#define HAVE_FEATURE_MACRO 1",
			},
		},
	}

	for _, tc := range testCases {
		buf := new(bytes.Buffer)
		if err := writeFeatureHeader(buf, tc.features, tc.common); err != nil {
			t.Error(err)
		}
		str := buf.String()

		for _, s := range tc.expectedLines {
			if !strings.Contains(str, s) {
				t.Errorf("expected %s to contain %s", str, s)
			}
		}
	}
}

func TestExecuteSystemConfigProbes(t *testing.T) {
	testutils.PrivilegedTest(t)

	if err := NewProbeManager(hivetest.Logger(t)).SystemConfigProbes(); err != nil {
		t.Error(err)
	}
}

func TestExecuteHeaderProbes(t *testing.T) {
	testutils.PrivilegedTest(t)

	if ExecuteHeaderProbes(hivetest.Logger(t)) == nil {
		t.Error("expected probes to not be nil")
	}
}

func TestSKBAdjustRoomL2RoomMACSupportProbe(t *testing.T) {
	testutils.PrivilegedTest(t)
	testutils.SkipOnOldKernel(t, "5.2", "BPF_ADJ_ROOM_MAC mode support in bpf_skb_adjust_room")
	assert.NoError(t, HaveSKBAdjustRoomL2RoomMACSupport(hivetest.Logger(t)))
}

func TestIPv6Support(t *testing.T) {
	assert.NoError(t, HaveIPv6Support())
}

func TestHaveBPF(t *testing.T) {
	testutils.PrivilegedTest(t)
	assert.NoError(t, HaveBPF())
}

func TestHaveBPFJIT(t *testing.T) {
	testutils.PrivilegedTest(t)
	assert.NoError(t, HaveBPFJIT())
}

func TestHaveDeadCodeElimSupport(t *testing.T) {
	testutils.PrivilegedTest(t)
	assert.NoError(t, HaveDeadCodeElim())
}

func TestHaveTCBPF(t *testing.T) {
	testutils.PrivilegedTest(t)
	assert.NoError(t, HaveTCBPF())
}

func TestHaveTCX(t *testing.T) {
	testutils.PrivilegedTest(t)
	testutils.SkipOnOldKernel(t, "6.6", "tcx bpf_link")
	assert.NoError(t, HaveTCX())
}

func TestHaveNetkit(t *testing.T) {
	testutils.PrivilegedTest(t)
	testutils.SkipOnOldKernel(t, "6.7", "netkit bpf_link")
	assert.NoError(t, HaveNetkit())
}
