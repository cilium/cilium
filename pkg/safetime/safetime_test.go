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

// +build !privileged_tests

package safetime

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type SafetimeSuite struct {
	out    *bytes.Buffer // stores log output
	logger *log.Entry
}

var _ = Suite(&SafetimeSuite{})

func (s *SafetimeSuite) SetUpTest(c *C) {
	s.out = &bytes.Buffer{}
	logger := log.New()
	logger.Out = s.out
	s.logger = log.NewEntry(logger)
}

func (s *SafetimeSuite) TestNegativeDuration(c *C) {
	future := time.Now().Add(time.Second)
	d, ok := TimeSinceSafe(future, s.logger)

	c.Assert(ok, Equals, false)
	c.Assert(d, Equals, time.Duration(0))
	fmt.Println(s.out.String())
	c.Assert(strings.Contains(s.out.String(), "BUG: negative duration"), Equals, true)
}

func (s *SafetimeSuite) TestNonNegativeDuration(c *C) {
	// To prevent the test case from being flaky on machines with invalid
	// CLOCK_MONOTONIC:
	past := time.Now().Add(-10 * time.Second)
	d, ok := TimeSinceSafe(past, s.logger)

	c.Assert(ok, Equals, true)
	c.Assert(d > time.Duration(0), Equals, true)
	c.Assert(len(s.out.String()) == 0, Equals, true)
}
