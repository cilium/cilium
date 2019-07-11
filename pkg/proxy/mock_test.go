// Copyright 2017-2019 Authors of Cilium
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

package proxy

import (
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

type proxyUpdaterMock struct {
	lock.RWMutex
	id              uint64
	ipv4            string
	ipv6            string
	labels          []string
	identity        identity.NumericIdentity
	hasSidecarProxy bool
}

func (m *proxyUpdaterMock) UnconditionalRLock() { m.RWMutex.RLock() }
func (m *proxyUpdaterMock) RUnlock()            { m.RWMutex.RUnlock() }

func (m *proxyUpdaterMock) GetID() uint64                         { return m.id }
func (m *proxyUpdaterMock) GetIPv4Address() string                { return m.ipv4 }
func (m *proxyUpdaterMock) GetIPv6Address() string                { return m.ipv6 }
func (m *proxyUpdaterMock) GetLabels() []string                   { return m.labels }
func (m *proxyUpdaterMock) GetEgressPolicyEnabledLocked() bool    { return true }
func (m *proxyUpdaterMock) GetIngressPolicyEnabledLocked() bool   { return true }
func (m *proxyUpdaterMock) GetIdentity() identity.NumericIdentity { return m.identity }
func (m *proxyUpdaterMock) ProxyID(l4 *policy.L4Filter) string    { return "" }
func (m *proxyUpdaterMock) GetLabelsSHA() string {
	return labels.NewLabelsFromModel(m.labels).SHA256Sum()
}
func (m *proxyUpdaterMock) HasSidecarProxy() bool { return m.hasSidecarProxy }
func (m *proxyUpdaterMock) ConntrackName() string { return "global" }

func (m *proxyUpdaterMock) OnProxyPolicyUpdate(policyRevision uint64) {}
func (m *proxyUpdaterMock) UpdateProxyStatistics(l4Protocol string, port uint16, ingress, request bool,
	verdict accesslog.FlowVerdict) {
}
