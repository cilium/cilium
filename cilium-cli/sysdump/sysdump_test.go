// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package sysdump

import (
	"path"
	"testing"
	"time"

	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type SysdumpSuite struct{}

var _ = check.Suite(&SysdumpSuite{})

func (b *SysdumpSuite) TestSysdumpCollector(c *check.C) {
	options := Options{
		OutputFileName: "my-sysdump-<ts>",
	}
	startTime := time.Unix(946713600, 0)
	timestamp := startTime.Format(timeFormat)
	collector, err := NewCollector(nil, options, startTime)
	c.Assert(err, check.IsNil)
	c.Assert(path.Base(collector.sysdumpDir), check.Equals, "my-sysdump-"+timestamp)
	tempFile := collector.AbsoluteTempPath("my-file-<ts>")
	c.Assert(tempFile, check.Equals, path.Join(collector.sysdumpDir, "my-file-"+timestamp))
}
