// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package probes

import (
	"errors"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type ProbesTestSuite struct{}

var _ = Suite(&ProbesTestSuite{})

func (s *ProbesTestSuite) TestSystemConfigProbes(c *C) {
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
		if errors.Is(err, ErrKernelConfigNotFound) {
			return
		}
		if tc.expectErr {
			c.Assert(err, NotNil)
		} else {
			c.Assert(err, IsNil)
		}
	}
}
