// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exec

import (
	"context"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging"
)

const (
	timeout = 250 * time.Millisecond
)

// Hook up gocheck into the "go test" runner.
type ExecTestSuite struct{}

var (
	_      = Suite(&ExecTestSuite{})
	fooLog = logging.DefaultLogger.WithField("foo", "bar")
)

func Test(t *testing.T) {
	TestingT(t)
}

func (s *ExecTestSuite) TestWithTimeout(c *C) {
	cmd := WithTimeout(timeout, "sleep", "inf")
	err := cmd.Start()
	c.Assert(err, IsNil)
	err = cmd.Wait()
	c.Assert(err, ErrorMatches, "signal: killed")
}

func (s *ExecTestSuite) TestWithCancel(c *C) {
	cmd, cancel := WithCancel(context.Background(), "sleep", "inf")
	c.Assert(cancel, NotNil)
	err := cmd.Start()
	c.Assert(err, IsNil)
	cancel()
}

func (s *ExecTestSuite) TestCanceled(c *C) {
	cmd, cancel := WithCancel(context.Background(), "sleep", "inf")
	c.Assert(cancel, NotNil)
	cancel()
	_, err := cmd.CombinedOutput(fooLog, true)
	c.Assert(err, ErrorMatches, ".*: context canceled")
}

func (s *ExecTestSuite) TestCombinedOutput(c *C) {
	cmd := CommandContext(context.Background(), "echo", "foo")
	out, err := cmd.CombinedOutput(fooLog, true)
	c.Assert(err, IsNil)
	c.Assert(string(out), Equals, "foo\n")
}

func (s *ExecTestSuite) TestCombinedOutputFailedTimeout(c *C) {
	cmd := WithTimeout(timeout, "sleep", "inf")
	time.Sleep(timeout)
	_, err := cmd.CombinedOutput(fooLog, true)
	c.Assert(err, ErrorMatches, "Command execution failed for .*: context deadline exceeded")
}

// LoggingHook is a simple hook which saves Warn messages to a slice of strings.
type LoggingHook struct {
	Lines []string
}

func (h *LoggingHook) Levels() []logrus.Level {
	// CombinedOutput logs stdout and stderr on WarnLevel.
	return []logrus.Level{
		logrus.WarnLevel,
	}
}

func (h *LoggingHook) Fire(entry *logrus.Entry) error {
	serializedEntry, err := entry.String()
	if err != nil {
		return err
	}
	h.Lines = append(h.Lines, serializedEntry)
	return nil
}
