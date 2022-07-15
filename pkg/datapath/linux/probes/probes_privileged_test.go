// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build privileged_tests

package probes

import (
	"bufio"
	"bytes"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type ProbesPrivTestSuite struct{}

var _ = Suite(&ProbesPrivTestSuite{})

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
