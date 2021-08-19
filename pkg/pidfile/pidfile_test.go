// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package pidfile

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/cilium/cilium/pkg/checker"

	. "gopkg.in/check.v1"
)

const (
	path = "/tmp/cilium-test-pidfile"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type PidfileTestSuite struct{}

var _ = Suite(&PidfileTestSuite{})

func (s *PidfileTestSuite) TestWrite(c *C) {
	err := Write(path)
	c.Assert(err, IsNil)
	defer Remove(path)

	content, err := os.ReadFile(path)
	c.Assert(err, IsNil)
	c.Assert(content, checker.DeepEquals, []byte(fmt.Sprintf("%d\n", os.Getpid())))
}

func (s *PidfileTestSuite) TestKill(c *C) {
	cmd := exec.Command("sleep", "inf")
	err := cmd.Start()
	c.Assert(err, IsNil)

	err = write(path, cmd.Process.Pid)
	c.Assert(err, IsNil)
	defer Remove(path)

	pid, err := Kill(path)
	c.Assert(err, IsNil)
	c.Assert(pid, Not(Equals), 0)

	err = cmd.Wait()
	c.Assert(err, ErrorMatches, "signal: killed")
}

func (s *PidfileTestSuite) TestKillAlreadyFinished(c *C) {
	cmd := exec.Command("sleep", "0")
	err := cmd.Start()
	c.Assert(err, IsNil)

	err = write(path, cmd.Process.Pid)
	c.Assert(err, IsNil)
	defer Remove(path)

	err = cmd.Wait()
	c.Assert(err, IsNil)

	pid, err := Kill(path)
	c.Assert(err, IsNil)
	c.Assert(pid, Equals, 0)
}

func (s *PidfileTestSuite) TestKillPidfileNotExist(c *C) {
	_, err := Kill("/tmp/cilium-foo-bar-some-not-existing-file")
	c.Assert(err, IsNil)
}

func (s *PidfileTestSuite) TestKillPidfilePermissionDenied(c *C) {
	err := os.WriteFile(path, []byte("foobar\n"), 0000)
	c.Assert(err, IsNil)
	defer Remove(path)

	_, err = Kill(path)
	c.Assert(err, ErrorMatches, ".* permission denied")
}

func (s *PidfileTestSuite) TestKillFailedParsePid(c *C) {
	err := os.WriteFile(path, []byte("foobar\n"), 0644)
	c.Assert(err, IsNil)
	defer Remove(path)

	_, err = Kill(path)
	c.Assert(err, ErrorMatches, "failed to parse pid .*")
}
