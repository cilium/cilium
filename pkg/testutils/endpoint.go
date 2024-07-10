// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"net/netip"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

var (
	defaultIdentity = identity.NewIdentity(42, labels.NewLabelsFromModel([]string{"foo"}))
	hostIdentity    = identity.NewIdentity(identity.ReservedIdentityHost, labels.LabelHost)
)

type TestEndpoint struct {
	Id          uint64
	Identity    *identity.Identity
	Opts        *option.IntOptions
	MAC         mac.MAC
	IfIndex     int
	IPv6        netip.Addr
	isHost      bool
	State       string
	NetNsCookie uint64
}

func NewTestEndpoint() TestEndpoint {
	opts := option.NewIntOptions(&option.OptionLibrary{})
	opts.SetBool("TEST_OPTION", true)
	return TestEndpoint{
		Id:          42,
		Identity:    defaultIdentity,
		MAC:         mac.MAC([]byte{0x02, 0x00, 0x60, 0x0D, 0xF0, 0x0D}),
		IfIndex:     0,
		Opts:        opts,
		NetNsCookie: 0,
	}
}

func NewTestHostEndpoint() TestEndpoint {
	opts := option.NewIntOptions(&option.OptionLibrary{})
	opts.SetBool("TEST_OPTION", true)
	return TestEndpoint{
		Id:       65535,
		Identity: hostIdentity,
		MAC:      mac.MAC([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}),
		IfIndex:  0,
		Opts:     opts,
		isHost:   true,
	}
}

func (e *TestEndpoint) ConntrackLocalLocked() bool                  { return false }
func (e *TestEndpoint) RequireARPPassthrough() bool                 { return false }
func (e *TestEndpoint) RequireEgressProg() bool                     { return false }
func (e *TestEndpoint) RequireRouting() bool                        { return false }
func (e *TestEndpoint) RequireEndpointRoute() bool                  { return false }
func (e *TestEndpoint) GetPolicyVerdictLogFilter() uint32           { return 0xffff }
func (e *TestEndpoint) GetCIDRPrefixLengths() ([]int, []int)        { return nil, nil }
func (e *TestEndpoint) GetID() uint64                               { return e.Id }
func (e *TestEndpoint) StringID() string                            { return "42" }
func (e *TestEndpoint) GetIdentity() identity.NumericIdentity       { return e.Identity.ID }
func (e *TestEndpoint) GetIdentityLocked() identity.NumericIdentity { return e.Identity.ID }
func (e *TestEndpoint) GetEndpointNetNsCookie() uint64              { return e.NetNsCookie }
func (e *TestEndpoint) GetSecurityIdentity() *identity.Identity     { return e.Identity }
func (e *TestEndpoint) GetNodeMAC() mac.MAC                         { return e.MAC }
func (e *TestEndpoint) GetIfIndex() int                             { return e.IfIndex }
func (e *TestEndpoint) GetOptions() *option.IntOptions              { return e.Opts }
func (e *TestEndpoint) IsHost() bool                                { return e.isHost }

func (e *TestEndpoint) IPv4Address() netip.Addr {
	return netip.MustParseAddr("192.0.2.3")
}
func (e *TestEndpoint) IPv6Address() netip.Addr {
	return e.IPv6
}

func (e *TestEndpoint) InterfaceName() string {
	return "cilium_test"
}

func (e *TestEndpoint) Logger(subsystem string) *logrus.Entry {
	return log
}

func (e *TestEndpoint) SetIdentity(secID int64, newEndpoint bool) {
	e.Identity = identity.NewIdentity(identity.NumericIdentity(secID), labels.NewLabelsFromModel([]string{"bar"}))
}

func (e *TestEndpoint) StateDir() string {
	if e.State != "" {
		return e.State
	}
	return "test_loader"
}
