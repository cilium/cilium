// Copyright 2018 Authors of Cilium
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

// +build privileged_tests

package probes

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type ProbesSuite struct{}

var _ = Suite(&ProbesSuite{})

func Test(t *testing.T) { TestingT(t) }

// changeConfigLocations changes lists of possible kernel config locations. It
// returns a function which restores old values.
func changeConfigLocations(configLocations, configLocationsGz []string) func() {
	oldLocalConfigLocations := localConfigLocations
	oldLocalConfigLocationsGz := localConfigLocationsGz

	localConfigLocations = configLocations
	localConfigLocationsGz = configLocationsGz

	return func() {
		localConfigLocations = oldLocalConfigLocations
		localConfigLocationsGz = oldLocalConfigLocationsGz
	}
}

func (s *ProbesSuite) TestReadKernelConfiguration(c *C) {
	var buf bytes.Buffer

	// Use example kernel config.
	finalizeFn := changeConfigLocations(
		[]string{"../../../bpf/examples/config"},
		nil,
	)
	defer finalizeFn()

	_, err := readKernelConfig(&buf)
	c.Assert(err, IsNil)
}

func (s *ProbesSuite) TestReadKernelConfigurationNotFound(c *C) {
	var buf bytes.Buffer

	finalizeFn := changeConfigLocations(
		[]string{"/foo/bar"},
		[]string{"/ayy/lmao.gz"},
	)
	defer finalizeFn()

	_, err := readKernelConfig(&buf)
	c.Assert(err, IsNil)
	c.Assert(buf.String(), Equals, "BPF/probes: Missing kernel configuration\n")
}

func (s *ProbesSuite) TestProbeKernelConfig(c *C) {
	var infoBuf, warningBuf bytes.Buffer

	// Use example kernel config.
	finalizeFn := changeConfigLocations(
		[]string{"../../../bpf/examples/config"},
		nil,
	)
	defer finalizeFn()

	err := probeKernelConfig(&infoBuf, &warningBuf)
	c.Assert(err, IsNil)
}

func (s *ProbesSuite) TestProbeRunLl(c *C) {
	var featureBuf, infoBuf bytes.Buffer

	// Create tempotary dir for probes.
	outDir, err := ioutil.TempDir("", "cilium-probes-out")
	c.Assert(err, IsNil)
	defer os.RemoveAll(outDir)

	err = probeRunLl(&featureBuf, &infoBuf, "../../../bpf/probes", "../../../bpf/include", outDir)
	c.Assert(err, IsNil)
}
