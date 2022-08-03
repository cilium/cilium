// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	"bufio"
	"bytes"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/testutils"
)

type ProbesPrivTestSuite struct{}

var _ = Suite(&ProbesPrivTestSuite{})

func (s *ProbesPrivTestSuite) SetUpSuite(c *C) {
	testutils.PrivilegedCheck(c)
}

func (s *ProbesPrivTestSuite) TestSystemConfigProbes(c *C) {
	pm := NewProbeManager()
	err := pm.SystemConfigProbes()
	c.Assert(err, IsNil)
}

func (s *ProbesPrivTestSuite) TestWriteHeaders(c *C) {
	var buf bytes.Buffer

	expectedPatterns := []string{
		"#ifndef BPF_FEATURES_H_",
		"#define BPF_FEATURES_H_",
		"#define HAVE_BPF_SYSCALL",
		"#define HAVE.*PROG_TYPE",
		"#define HAVE.*MAP_TYPE",
		"#define HAVE_PROG_TYPE_HELPER\\(prog_type, helper\\)",
		"#define BPF__PROG_TYPE_.*__HELPER_.* [01]",
		"#endif /\\* BPF_FEATURES_H_ \\*/",
	}

	writer := bufio.NewWriter(&buf)
	pm := NewProbeManager()
	pm.writeHeaders(writer)
	content := buf.String()

	for _, pattern := range expectedPatterns {
		c.Assert(content, checker.PartialMatches, pattern)
	}
}
