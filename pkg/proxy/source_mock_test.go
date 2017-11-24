// Copyright 2017 Authors of Cilium
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

package proxy

import (
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"
)

type proxySourceMocker struct {
	lock.RWMutex
	id       uint64
	ipv4     string
	ipv6     string
	labels   []string
	identity policy.NumericIdentity
}

func (m *proxySourceMocker) RLock()   { m.RWMutex.RLock() }
func (m *proxySourceMocker) RUnlock() { m.RWMutex.RUnlock() }

func (m *proxySourceMocker) GetID() uint64                       { return m.id }
func (m *proxySourceMocker) GetIPv4Address() string              { return m.ipv4 }
func (m *proxySourceMocker) GetIPv6Address() string              { return m.ipv6 }
func (m *proxySourceMocker) GetLabels() []string                 { return m.labels }
func (m *proxySourceMocker) GetIdentity() policy.NumericIdentity { return m.identity }

func (m *proxySourceMocker) GetLabelsSHA() string {
	return labels.NewLabelsFromModel(m.labels).SHA256Sum()
}

func (m *proxySourceMocker) ResolveIdentity(policy.NumericIdentity) *policy.Identity {
	return policy.NewIdentity(m.identity, labels.NewLabelsFromModel(m.labels))
}
