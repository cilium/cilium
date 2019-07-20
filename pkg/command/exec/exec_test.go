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

package exec

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/logging"

	"github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
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

func (s *ExecTestSuite) TestWithFilters(c *C) {
	hook := &LoggingHook{}
	logging.DefaultLogger.Hooks.Add(hook)
	logging.DefaultLogger.SetLevel(logrus.WarnLevel)
	defer logging.DefaultLogger.SetLevel(logging.LevelStringToLogrusLevel[logging.DefaultLogLevelStr])

	// This command will print the following output to stderr:
	//
	// cat: /some/non/existing/file: No such file or directory
	// cat: /non/existing/file/filtered/out: No such file or directory
	//
	// But the second message should be filtered out from logging.
	cmd := CommandContext(context.Background(),
		"cat",
		"/non/existing/file",
		"/non/existing/file/filtered/out").WithFilters("/filtered/out")
	scopedLog := logging.DefaultLogger.WithField("foo", "bar")
	out, err := cmd.CombinedOutput(scopedLog, true)
	c.Assert(err, ErrorMatches, "exit status 1")

	// Both errors be returned by CombinedOutput.
	expectedOut := `cat: /non/existing/file: No such file or directory
cat: /non/existing/file/filtered/out: No such file or directory
`
	c.Assert(string(out), Equals, expectedOut)

	// The last error message should be filtered out from logging.
	logLines := []string{
		"level=warning msg=\"cat: /non/existing/file: No such file or directory\" foo=bar\n",
	}
	c.Assert(hook.Lines, checker.DeepEquals, logLines)
}
