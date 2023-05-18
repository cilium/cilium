// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package safetime

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	"github.com/sirupsen/logrus"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type SafetimeSuite struct {
	out    *bytes.Buffer // stores log output
	logger *logrus.Entry
}

var _ = Suite(&SafetimeSuite{})

func (s *SafetimeSuite) SetUpTest(c *C) {
	s.out = &bytes.Buffer{}
	logger := logrus.New()
	logger.Out = s.out
	s.logger = logrus.NewEntry(logger)
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
