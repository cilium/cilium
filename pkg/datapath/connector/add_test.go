// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package connector

import (
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

// recordingSysctl is a minimal sysctl.Sysctl implementation that records the
// parameters written by Disable/Enable so tests can assert on the relaxations
// applied to an endpoint interface.
type recordingSysctl struct {
	// written maps the dotted sysctl name to the value written ("0" for
	// Disable, "1" for Enable).
	written map[string]string
}

func newRecordingSysctl() *recordingSysctl {
	return &recordingSysctl{written: map[string]string{}}
}

func key(name []string) string { return strings.Join(name, ".") }

func (s *recordingSysctl) Disable(name []string) error {
	s.written[key(name)] = "0"
	return nil
}

func (s *recordingSysctl) Enable(name []string) error {
	s.written[key(name)] = "1"
	return nil
}

func (s *recordingSysctl) Write(name []string, val string) error {
	s.written[key(name)] = val
	return nil
}

func (s *recordingSysctl) WriteInt(name []string, val int64) error {
	if val == 0 {
		s.written[key(name)] = "0"
	} else {
		s.written[key(name)] = "1"
	}
	return nil
}

func (s *recordingSysctl) ApplySettings(sysSettings []tables.Sysctl) error {
	for _, ss := range sysSettings {
		s.written[key(ss.Name)] = ss.Val
	}
	return nil
}

func (s *recordingSysctl) Read(name []string) (string, error) {
	if v, ok := s.written[key(name)]; ok {
		return v, nil
	}
	return "", nil
}

func (s *recordingSysctl) ReadInt(name []string) (int64, error) {
	if v, ok := s.written[key(name)]; ok && v != "0" {
		return 1, nil
	}
	return 0, nil
}

// TestDisableRpFilter asserts that relaxing the reverse-path check on an
// endpoint interface disables rp_filter AND enables accept_local. Both are
// required so that proxy-redirected (stack-TPROXY) packets, whose mark routes
// them via the proxy "local default dev lo" table, are not dropped as a
// martian source during fib_validate_source. See cilium/cilium#46260.
func TestDisableRpFilter(t *testing.T) {
	ctl := newRecordingSysctl()

	require.NoError(t, DisableRpFilter(ctl, "lxc12345"))

	assert.Equal(t, "0", ctl.written["net.ipv4.conf.lxc12345.rp_filter"],
		"rp_filter must be disabled on the endpoint interface")
	assert.Equal(t, "1", ctl.written["net.ipv4.conf.lxc12345.accept_local"],
		"accept_local must be enabled on the endpoint interface to avoid martian-source drops on the proxy redirect path (#46260)")
}

// TestDisableRpFilterParameters guards the exact sysctl parameter paths so a
// rename of the interface argument cannot silently target the wrong device.
func TestDisableRpFilterParameters(t *testing.T) {
	ctl := newRecordingSysctl()

	require.NoError(t, DisableRpFilter(ctl, "lxcABCDE"))

	var keys []string
	for k := range ctl.written {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	assert.Equal(t, []string{
		"net.ipv4.conf.lxcABCDE.accept_local",
		"net.ipv4.conf.lxcABCDE.rp_filter",
	}, keys)
}
