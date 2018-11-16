// Copyright 2018 Authors of Cilium
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

package endpoint

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/revert"

	. "gopkg.in/check.v1"
)

type EndpointTestOwner struct {

	// Owners interface mock
	OnTracingEnabled          func() bool
	OnAlwaysAllowLocalhost    func() bool
	OnGetCachedLabelList      func(id identity.NumericIdentity) (labels.LabelArray, error)
	OnGetPolicyRepository     func() *policy.Repository
	OnUpdateProxyRedirect     func(e *Endpoint, l4 *policy.L4Filter, proxyWaitGroup *completion.WaitGroup) (uint16, error, revert.FinalizeFunc, revert.RevertFunc)
	OnRemoveProxyRedirect     func(e *Endpoint, id string, proxyWaitGroup *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc)
	OnUpdateNetworkPolicy     func(e *Endpoint, policy *policy.L4Policy, labelsMap cache.IdentityCache, deniedIngressIdentities, deniedEgressIdentities map[identity.NumericIdentity]bool, proxyWaitGroup *completion.WaitGroup) (error, revert.RevertFunc)
	OnRemoveNetworkPolicy     func(e *Endpoint)
	OnQueueEndpointBuild      func(epID uint64) func()
	OnRemoveFromEndpointQueue func(epID uint64)
	OnDebugEnabled            func() bool
	OnGetCompilationLock      func() *lock.RWMutex
	OnSendNotification        func(typ monitor.AgentNotification, text string) error
	OnNewProxyLogRecord       func(l *accesslog.LogRecord) error
}

var (
	repo = &policy.Repository{}
)

func SetupEndpointTestOwner() *EndpointTestOwner {

	endpointTestOwner := EndpointTestOwner{}

	endpointTestOwner.OnTracingEnabled = nil
	endpointTestOwner.OnAlwaysAllowLocalhost = nil
	endpointTestOwner.OnGetCachedLabelList = nil

	endpointTestOwner.OnGetPolicyRepository = func() *policy.Repository {
		return repo
	}
	endpointTestOwner.OnUpdateProxyRedirect = nil
	endpointTestOwner.OnRemoveProxyRedirect = nil
	endpointTestOwner.OnUpdateNetworkPolicy = nil
	endpointTestOwner.OnRemoveNetworkPolicy = nil
	endpointTestOwner.OnQueueEndpointBuild = nil
	endpointTestOwner.OnRemoveFromEndpointQueue = nil
	endpointTestOwner.OnDebugEnabled = nil
	endpointTestOwner.OnGetCompilationLock = nil
	endpointTestOwner.OnSendNotification = nil
	endpointTestOwner.OnNewProxyLogRecord = nil

	cache.InitIdentityAllocator(endpointTestOwner)

	return &endpointTestOwner
}

var (
	endpointTestOwner *EndpointTestOwner
	ep                *Endpoint
)

func (e *EndpointSuite) SetUpSuite(c *C) {
	kvstore.SetupDummy("etcd")
	policy.SetPolicyEnabled(option.DefaultEnforcement)
	endpointTestOwner = SetupEndpointTestOwner()
	ep = endpointCreator(256, identity.NumericIdentity(256))
	repo.AddList(GenerateNumRules(1000000))

}

func (e *EndpointSuite) TearDownSuite(c *C) {
	repo = &policy.Repository{}
	kvstore.DeletePrefix(common.OperationalPath)
	kvstore.DeletePrefix(kvstore.BaseKeyPrefix)
}

// IdentityAllocatorOwner
func (owner EndpointTestOwner) TriggerPolicyUpdates(force bool, reason string) *sync.WaitGroup {
	return nil
}

func (owner EndpointTestOwner) GetNodeSuffix() string {
	return "foo"
}

//Owner
func (owner *EndpointTestOwner) GetPolicyRepository() *policy.Repository {
	return owner.OnGetPolicyRepository()
}

func (owner *EndpointTestOwner) AlwaysAllowLocalhost() bool {
	if owner.OnAlwaysAllowLocalhost != nil {
		return owner.OnAlwaysAllowLocalhost()
	}
	panic("AlwaysAllowLocalhost should not have been called")
}

func (owner *EndpointTestOwner) GetCachedLabelList(id identity.NumericIdentity) (labels.LabelArray, error) {
	if owner.OnGetCachedLabelList != nil {
		return owner.OnGetCachedLabelList(id)
	}
	panic("GetCachedLabelList should not have been called")
}

func (owner *EndpointTestOwner) UpdateProxyRedirect(e *Endpoint, l4 *policy.L4Filter, proxyWaitGroup *completion.WaitGroup) (uint16, error, revert.FinalizeFunc, revert.RevertFunc) {
	if owner.OnUpdateProxyRedirect != nil {
		return owner.OnUpdateProxyRedirect(e, l4, proxyWaitGroup)
	}
	panic("UpdateProxyRedirect should not have been called")
}

func (owner *EndpointTestOwner) RemoveProxyRedirect(e *Endpoint, id string, proxyWaitGroup *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	if owner.OnRemoveProxyRedirect != nil {
		return owner.OnRemoveProxyRedirect(e, id, proxyWaitGroup)
	}
	panic("RemoveProxyRedirect should not have been called")
}

func (owner *EndpointTestOwner) UpdateNetworkPolicy(e *Endpoint, policy *policy.L4Policy,
	labelsMap cache.IdentityCache, deniedIngressIdentities, deniedEgressIdentities map[identity.NumericIdentity]bool, proxyWaitGroup *completion.WaitGroup) (error, revert.RevertFunc) {
	if owner.OnUpdateNetworkPolicy != nil {
		return owner.OnUpdateNetworkPolicy(e, policy, labelsMap, deniedIngressIdentities, deniedEgressIdentities, proxyWaitGroup)
	}
	panic("UpdateNetworkPolicy should not have been called")
}

func (owner *EndpointTestOwner) RemoveNetworkPolicy(e *Endpoint) {
	if owner.OnRemoveNetworkPolicy != nil {
		owner.OnRemoveNetworkPolicy(e)
	}
	panic("RemoveNetworkPolicy should not have been called")
}

func (owner *EndpointTestOwner) QueueEndpointBuild(epID uint64) func() {
	if owner.OnQueueEndpointBuild != nil {
		owner.OnQueueEndpointBuild(epID)
		return func() { return }
	}
	panic("QueueEndpointBuild should not have been called")
}

func (owner *EndpointTestOwner) RemoveFromEndpointQueue(epID uint64) {
	if owner.OnRemoveFromEndpointQueue != nil {
		owner.OnRemoveFromEndpointQueue(epID)
		return
	}
	panic("RemoveFromEndpointQueue should not have been called")
}

func (owner *EndpointTestOwner) DebugEnabled() bool {
	if owner.OnDebugEnabled != nil {
		return owner.OnDebugEnabled()
	}
	panic("DebugEnabled should not have been called")
}

func (owner *EndpointTestOwner) GetCompilationLock() *lock.RWMutex {
	if owner.OnGetCompilationLock != nil {
		return owner.OnGetCompilationLock()
	}
	panic("GetCompilationLock should not have been called")
}

func (owner *EndpointTestOwner) SendNotification(typ monitor.AgentNotification, text string) error {
	if owner.OnSendNotification != nil {
		return owner.OnSendNotification(typ, text)
	}
	panic("SendNotification should not have been called")
}

func (owner *EndpointTestOwner) NewProxyLogRecord(l *accesslog.LogRecord) error {
	if owner.OnNewProxyLogRecord != nil {
		return owner.OnNewProxyLogRecord(l)
	}
	panic("NewProxyLogRecord should not have been called")
}

func (s *EndpointSuite) BenchmarkRegeneratePolicyRules(c *C) {
	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		ep.regeneratePolicy(endpointTestOwner)
		ep.forcePolicyCompute = true
	}
}

func getStrID(id uint16) string {
	return fmt.Sprintf("%05d", id)
}

func endpointCreator(id uint16, secID identity.NumericIdentity) *Endpoint {
	strID := getStrID(id)
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, id)

	ep := NewEndpointWithState(id, StateReady)
	// Random network ID and docker endpoint ID with 59 hex chars + 5 strID = 64 hex chars
	ep.DockerNetworkID = "603e047d2268a57f5a5f93f7f9e1263e9207e348a06654bf64948def001" + strID
	ep.DockerEndpointID = "93529fda8c401a071d21d6bd46fdf5499b9014dcb5a35f2e3efaa8d8002" + strID
	ep.IfName = "lxc" + strID
	ep.LXCMAC = mac.MAC([]byte{0x01, 0xff, 0xf2, 0x12, b[0], b[1]})
	ep.IPv4 = addressing.DeriveCiliumIPv4(net.IP{0xc0, 0xa8, b[0], b[1]})
	ep.IPv6 = addressing.DeriveCiliumIPv6(net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, b[0], b[1]})
	ep.IfIndex = 1
	ep.NodeMAC = mac.MAC([]byte{0x02, 0xff, 0xf2, 0x12, 0x0, 0x0})
	fooLabel := labels.NewLabel("k8s:foo", "", "")
	lbls := labels.Labels{
		"foo": fooLabel,
	}
	ep.SecurityIdentity = &identity.Identity{
		ID:         secID,
		Labels:     lbls,
		LabelArray: lbls.LabelArray(),
	}
	ep.OpLabels = labels.NewOpLabels()
	return ep
}

func GenerateNumRules(numRules int) api.Rules {
	parseFooLabel := labels.ParseSelectLabel("k8s:foo")
	fooSelector := api.NewESFromLabels(parseFooLabel)
	barSelector := api.NewESFromLabels(labels.ParseSelectLabel("bar"))

	// Change ingRule and rule in the for-loop below to change what type of rules
	// are added into the policy repository.
	ingRule := api.IngressRule{
		FromEndpoints: []api.EndpointSelector{barSelector},
		/*FromRequires:  []api.EndpointSelector{barSelector},
		ToPorts: []api.PortRule{
			{
				Ports: []api.PortProtocol{
					{
						Port:     "8080",
						Protocol: api.ProtoTCP,
					},
				},
			},
		},*/
	}

	var rules api.Rules
	for i := 1; i <= numRules; i++ {

		rule := api.Rule{
			EndpointSelector: fooSelector,
			Ingress:          []api.IngressRule{ingRule},
		}

		rules = append(rules, &rule)
	}
	return rules
}
