// Copyright 2019 Authors of Cilium
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

package testutils

import (
	identityMdl "github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
)

var (
	defaultIdentity = identity.NewIdentityFromModel(&identityMdl.Identity{
		ID:     42,
		Labels: []string{"foo"},
	})
)

type TestEndpoint struct {
	Id       uint64
	Identity *identity.Identity
	Opts     *option.IntOptions
	MAC      mac.MAC
}

func NewTestEndpoint() TestEndpoint {
	opts := option.NewIntOptions(&option.OptionLibrary{})
	opts.SetBool("TEST_OPTION", true)
	return TestEndpoint{
		Id:       42,
		Identity: defaultIdentity,
		MAC:      mac.MAC([]byte{0x02, 0x00, 0x60, 0x0D, 0xF0, 0x0D}),
		Opts:     opts,
	}
}

func (e *TestEndpoint) HasIpvlanDataPath() bool                 { return false }
func (e *TestEndpoint) ConntrackLocalLocked() bool              { return false }
func (e *TestEndpoint) RequireARPPassthrough() bool             { return false }
func (e *TestEndpoint) GetCIDRPrefixLengths() ([]int, []int)    { return nil, nil }
func (e *TestEndpoint) GetID() uint64                           { return e.Id }
func (e *TestEndpoint) StringID() string                        { return "42" }
func (e *TestEndpoint) GetIdentity() identity.NumericIdentity   { return e.Identity.ID }
func (e *TestEndpoint) GetSecurityIdentity() *identity.Identity { return e.Identity }
func (e *TestEndpoint) GetNodeMAC() mac.MAC                     { return e.MAC }
func (e *TestEndpoint) GetOptions() *option.IntOptions          { return e.Opts }

func (e *TestEndpoint) IPv4Address() addressing.CiliumIPv4 {
	addr, _ := addressing.NewCiliumIPv4("192.0.2.3")
	return addr
}
func (e *TestEndpoint) IPv6Address() addressing.CiliumIPv6 {
	addr, _ := addressing.NewCiliumIPv6("2001:db08:0bad:cafe:600d:bee2:0bad:cafe")
	return addr
}

func (e *TestEndpoint) InterfaceName() string {
	return "cilium_test"
}

func (e *TestEndpoint) Logger(subsystem string) *logrus.Entry {
	return log
}

func (e *TestEndpoint) SetIdentity(secID int64) {
	e.Identity = identity.NewIdentityFromModel(&identityMdl.Identity{
		ID:     secID,
		Labels: []string{"bar"},
	})
}

func (e *TestEndpoint) StateDir() string {
	return "test_loader"
}

func (e *TestEndpoint) MapPath() string {
	return "map_path"
}
