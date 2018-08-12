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
//
// +build privileged_tests

package probes

import (
	"os"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/logging"

	"github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type ProbesTestSuite struct {
	origWorkingDir string
}

var _ = Suite(&ProbesTestSuite{})

func (p *ProbesTestSuite) SetupTest(c *C) {
	wd, err := os.Getwd()
	c.Assert(err, IsNil)
	p.origWorkingDir = wd
}

// TestProbes compiles, loads and unloads all probes
func (p *ProbesTestSuite) TestProbes(c *C) {
	logging.DefaultLogger.SetLevel(logrus.DebugLevel)
	c.Assert(os.Chdir("../../bpf"), IsNil)
	Init()

	time.Sleep(300 * time.Second)
}

func (p *ProbesTestSuite) TearDownTest(c *C) {
	os.Chdir(p.origWorkingDir)
	Close()
}
