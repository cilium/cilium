// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"testing"

	. "gopkg.in/check.v1"

	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/version"
	"github.com/cilium/cilium/pkg/versioncheck"
)

// Hook up gocheck into the "go test" runner.
type IPCacheMapTestSuite struct{}

var _ = Suite(&IPCacheMapTestSuite{})

func init() {
}

func Test(t *testing.T) {
	TestingT(t)
}

func (k *IPCacheMapTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedCheck(c)

	logging.SetLogLevelToDebug()
	bpf.CheckOrMountFS("")
	err := rlimit.RemoveMemlock()
	c.Assert(err, IsNil)
}

func (k *IPCacheMapTestSuite) Test_SupportsDelete(c *C) {
	ver, err := version.GetKernelVersion()
	c.Assert(err, IsNil)
	constraint, err := versioncheck.Compile(">=4.15.0")
	c.Assert(err, IsNil)
	c.Assert(SupportsDelete(), Equals, constraint(ver))
}
