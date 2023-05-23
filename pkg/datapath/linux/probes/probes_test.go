// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestSystemConfigProbes(t *testing.T) {
	testCases := []struct {
		systemConfig SystemConfig
		expectErr    bool
	}{
		{
			systemConfig: SystemConfig{
				ConfigBpf:           "y",
				ConfigBpfSyscall:    "y",
				ConfigNetSchIngress: "y",
				ConfigNetClsBpf:     "y",
				ConfigNetClsAct:     "y",
				ConfigBpfJit:        "y",
				ConfigHaveEbpfJit:   "y",
				ConfigCgroupBpf:     "y",
				ConfigLwtunnelBpf:   "y",
				ConfigBpfEvents:     "y",
			},
			expectErr: false,
		},
		{
			systemConfig: SystemConfig{
				ConfigBpf:           "y",
				ConfigBpfSyscall:    "y",
				ConfigNetSchIngress: "m",
				ConfigNetClsBpf:     "m",
				ConfigNetClsAct:     "y",
				ConfigBpfJit:        "y",
				ConfigHaveEbpfJit:   "y",
				ConfigCgroupBpf:     "y",
				ConfigLwtunnelBpf:   "y",
				ConfigBpfEvents:     "y",
			},
			expectErr: false,
		},
		// Disable options which generate errors
		{
			systemConfig: SystemConfig{
				ConfigBpf:           "n",
				ConfigBpfSyscall:    "n",
				ConfigNetSchIngress: "n",
				ConfigNetClsBpf:     "n",
				ConfigNetClsAct:     "n",
				ConfigBpfJit:        "n",
				ConfigHaveEbpfJit:   "n",
				ConfigCgroupBpf:     "n",
				ConfigLwtunnelBpf:   "n",
				ConfigBpfEvents:     "n",
			},
			expectErr: true,
		},
		{
			systemConfig: SystemConfig{
				ConfigBpf:           "n",
				ConfigBpfSyscall:    "y",
				ConfigNetSchIngress: "y",
				ConfigNetClsBpf:     "y",
				ConfigNetClsAct:     "y",
				ConfigBpfJit:        "y",
				ConfigHaveEbpfJit:   "y",
				ConfigCgroupBpf:     "y",
				ConfigLwtunnelBpf:   "y",
				ConfigBpfEvents:     "y",
			},
			expectErr: true,
		},
		{
			systemConfig: SystemConfig{
				ConfigBpf:           "y",
				ConfigBpfSyscall:    "n",
				ConfigNetSchIngress: "y",
				ConfigNetClsBpf:     "y",
				ConfigNetClsAct:     "y",
				ConfigBpfJit:        "y",
				ConfigHaveEbpfJit:   "y",
				ConfigCgroupBpf:     "y",
				ConfigLwtunnelBpf:   "y",
				ConfigBpfEvents:     "y",
			},
			expectErr: true,
		},
		{
			systemConfig: SystemConfig{
				ConfigBpf:           "y",
				ConfigBpfSyscall:    "y",
				ConfigNetSchIngress: "n",
				ConfigNetClsBpf:     "y",
				ConfigNetClsAct:     "y",
				ConfigBpfJit:        "y",
				ConfigHaveEbpfJit:   "y",
				ConfigCgroupBpf:     "y",
				ConfigLwtunnelBpf:   "y",
				ConfigBpfEvents:     "y",
			},
			expectErr: true,
		},
		{
			systemConfig: SystemConfig{
				ConfigBpf:           "y",
				ConfigBpfSyscall:    "y",
				ConfigNetSchIngress: "y",
				ConfigNetClsBpf:     "n",
				ConfigNetClsAct:     "y",
				ConfigBpfJit:        "y",
				ConfigHaveEbpfJit:   "y",
				ConfigCgroupBpf:     "y",
				ConfigLwtunnelBpf:   "y",
				ConfigBpfEvents:     "y",
			},
			expectErr: true,
		},
		{
			systemConfig: SystemConfig{
				ConfigBpf:           "y",
				ConfigBpfSyscall:    "y",
				ConfigNetSchIngress: "y",
				ConfigNetClsBpf:     "y",
				ConfigNetClsAct:     "n",
				ConfigBpfJit:        "y",
				ConfigHaveEbpfJit:   "y",
				ConfigCgroupBpf:     "y",
				ConfigLwtunnelBpf:   "y",
				ConfigBpfEvents:     "y",
			},
			expectErr: true,
		},
		{
			systemConfig: SystemConfig{
				ConfigBpf:           "y",
				ConfigBpfSyscall:    "y",
				ConfigNetSchIngress: "y",
				ConfigNetClsBpf:     "y",
				ConfigNetClsAct:     "y",
				ConfigBpfJit:        "n",
				ConfigHaveEbpfJit:   "y",
				ConfigCgroupBpf:     "y",
				ConfigLwtunnelBpf:   "y",
				ConfigBpfEvents:     "y",
			},
			expectErr: true,
		},
		{
			systemConfig: SystemConfig{
				ConfigBpf:           "y",
				ConfigBpfSyscall:    "y",
				ConfigNetSchIngress: "y",
				ConfigNetClsBpf:     "y",
				ConfigNetClsAct:     "y",
				ConfigBpfJit:        "y",
				ConfigHaveEbpfJit:   "n",
				ConfigCgroupBpf:     "y",
				ConfigLwtunnelBpf:   "y",
				ConfigBpfEvents:     "y",
			},
			expectErr: true,
		},
		// Disable options which generate warnings
		{
			systemConfig: SystemConfig{
				ConfigBpf:           "y",
				ConfigBpfSyscall:    "y",
				ConfigNetSchIngress: "y",
				ConfigNetClsBpf:     "y",
				ConfigNetClsAct:     "y",
				ConfigBpfJit:        "y",
				ConfigHaveEbpfJit:   "y",
				ConfigCgroupBpf:     "n",
				ConfigLwtunnelBpf:   "n",
				ConfigBpfEvents:     "n",
			},
			expectErr: false,
		},
		{
			systemConfig: SystemConfig{
				ConfigBpf:           "y",
				ConfigBpfSyscall:    "y",
				ConfigNetSchIngress: "y",
				ConfigNetClsBpf:     "y",
				ConfigNetClsAct:     "y",
				ConfigBpfJit:        "y",
				ConfigHaveEbpfJit:   "y",
				ConfigCgroupBpf:     "n",
				ConfigLwtunnelBpf:   "y",
				ConfigBpfEvents:     "y",
			},
			expectErr: false,
		},
		{
			systemConfig: SystemConfig{
				ConfigBpf:           "y",
				ConfigBpfSyscall:    "y",
				ConfigNetSchIngress: "y",
				ConfigNetClsBpf:     "y",
				ConfigNetClsAct:     "y",
				ConfigBpfJit:        "y",
				ConfigHaveEbpfJit:   "y",
				ConfigCgroupBpf:     "y",
				ConfigLwtunnelBpf:   "n",
				ConfigBpfEvents:     "y",
			},
			expectErr: false,
		},
		{
			systemConfig: SystemConfig{
				ConfigBpf:           "y",
				ConfigBpfSyscall:    "y",
				ConfigNetSchIngress: "y",
				ConfigNetClsBpf:     "y",
				ConfigNetClsAct:     "y",
				ConfigBpfJit:        "y",
				ConfigHaveEbpfJit:   "y",
				ConfigCgroupBpf:     "y",
				ConfigLwtunnelBpf:   "y",
				ConfigBpfEvents:     "n",
			},
			expectErr: false,
		},
	}
	for _, tc := range testCases {
		manager := &ProbeManager{
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
				"HAVE_FIB_LOOKUP": true,
			},
			common: true,
			expectedLines: []string{
				"#define HAVE_FIB_LOOKUP 1",
			},
		},
		{
			features: map[string]bool{
				"HAVE_FIB_LOOKUP": true,
			},
			common: false,
			expectedLines: []string{
				"#include \"features.h\"",
				"#define HAVE_FIB_LOOKUP 1",
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

	if err := NewProbeManager().SystemConfigProbes(); err != nil {
		t.Error(err)
	}
}

func TestExecuteHeaderProbes(t *testing.T) {
	testutils.PrivilegedTest(t)

	if ExecuteHeaderProbes() == nil {
		t.Error("expected probes to not be nil")
	}
}

func TestOuterSourceIPProbe(t *testing.T) {
	testutils.PrivilegedTest(t)
	testutils.SkipOnOldKernel(t, "5.19", "source IP support in struct bpf_tunnel_key")

	if err := HaveOuterSourceIPSupport(); err != nil {
		t.Fatal(err)
	}
}

func TestIPv6Support(t *testing.T) {
	if err := HaveIPv6Support(); err != nil {
		t.Fatal(err)
	}
}
