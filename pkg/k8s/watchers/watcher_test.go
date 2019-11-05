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

// +build !privileged_tests

package watchers

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type K8sWatcherSuite struct{}

var _ = Suite(&K8sWatcherSuite{})

type fakeEndpointManager struct {
	OnGetEndpoints                func() []*endpoint.Endpoint
	OnLookupPodName               func(string) *endpoint.Endpoint
	OnWaitForEndpointsAtPolicyRev func(ctx context.Context, rev uint64) error
}

func (f *fakeEndpointManager) GetEndpoints() []*endpoint.Endpoint {
	if f.OnGetEndpoints != nil {
		return f.OnGetEndpoints()
	}
	panic("OnGetEndpoints was called and is not set!")
}

func (f *fakeEndpointManager) LookupPodName(podName string) *endpoint.Endpoint {
	if f.OnLookupPodName != nil {
		return f.OnLookupPodName(podName)
	}
	panic("OnLookupPodName(string) was called and is not set!")
}

func (f *fakeEndpointManager) WaitForEndpointsAtPolicyRev(ctx context.Context, rev uint64) error {
	if f.OnWaitForEndpointsAtPolicyRev != nil {
		return f.OnWaitForEndpointsAtPolicyRev(ctx, rev)
	}
	panic("OnWaitForEndpointsAtPolicyRev(context.Context, uint64) was called and is not set!")
}

type fakeNodeDiscoverManager struct {
	OnNodeDeleted                  func(n node.Node)
	OnNodeUpdated                  func(n node.Node)
	OnClusterSizeDependantInterval func(baseInterval time.Duration) time.Duration
}

func (f *fakeNodeDiscoverManager) NodeDeleted(n node.Node) {
	if f.OnNodeDeleted != nil {
		f.OnNodeDeleted(n)
		return
	}
	panic("OnNodeDeleted(node) was called and is not set!")
}

func (f *fakeNodeDiscoverManager) NodeUpdated(n node.Node) {
	if f.OnNodeUpdated != nil {
		f.OnNodeUpdated(n)
		return
	}
	panic("OnNodeUpdated(node) was called and is not set!")
}

func (f *fakeNodeDiscoverManager) ClusterSizeDependantInterval(baseInterval time.Duration) time.Duration {
	if f.OnClusterSizeDependantInterval != nil {
		return f.OnClusterSizeDependantInterval(baseInterval)
	}
	panic("OnClusterSizeDependantInterval(time.Duration) was called and is not set!")
}

type fakePolicyManager struct {
	OnTriggerPolicyUpdates func(force bool, reason string)
	OnPolicyAdd            func(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error)
	OnPolicyDelete         func(labels labels.LabelArray) (newRev uint64, err error)
}

func (f *fakePolicyManager) TriggerPolicyUpdates(force bool, reason string) {
	if f.OnTriggerPolicyUpdates != nil {
		f.OnTriggerPolicyUpdates(force, reason)
		return
	}
	panic("OnTriggerPolicyUpdates(force bool, reason string) was called and is not set!")
}

func (f *fakePolicyManager) PolicyAdd(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error) {
	if f.OnPolicyAdd != nil {
		return f.OnPolicyAdd(rules, opts)
	}
	panic("OnPolicyAdd(api.Rules, *policy.AddOptions) (uint64, error) was called and is not set!")
}

func (f *fakePolicyManager) PolicyDelete(labels labels.LabelArray) (newRev uint64, err error) {
	if f.OnPolicyDelete != nil {
		return f.OnPolicyDelete(labels)
	}
	panic("OnPolicyDelete(labels.LabelArray) (uint64, error) was called and is not set!")
}

type fakePolicyRepository struct {
	OnTranslateRules func(translator policy.Translator) (*policy.TranslationResult, error)
}

func (f *fakePolicyRepository) TranslateRules(translator policy.Translator) (*policy.TranslationResult, error) {
	if f.OnTranslateRules != nil {
		return f.OnTranslateRules(translator)
	}
	panic("OnTranslateRules(policy.Translator) (*policy.TranslationResult, error) was called and is not set!")
}

type fakeSvcManager struct {
	OnDeleteService func(frontend loadbalancer.L3n4Addr) (bool, error)
	OnUpsertService func(frontend loadbalancer.L3n4AddrID, backends []loadbalancer.Backend,
		svcType loadbalancer.SVCType, svcName, svcNamespace string) (bool, loadbalancer.ID, error)
}

func (f *fakeSvcManager) DeleteService(frontend loadbalancer.L3n4Addr) (bool, error) {
	if f.OnDeleteService != nil {
		return f.OnDeleteService(frontend)
	}
	panic("OnDeleteService(loadbalancer.L3n4Addr) (bool, error) was called and is not set!")
}

func (f *fakeSvcManager) UpsertService(frontend loadbalancer.L3n4AddrID, backends []loadbalancer.Backend,
	svcType loadbalancer.SVCType, svcName, svcNamespace string) (bool, loadbalancer.ID, error) {
	if f.OnUpsertService != nil {
		return f.OnUpsertService(frontend, backends, svcType, svcName, svcNamespace)
	}
	panic("OnUpsertService(loadbalancer.L3n4AddrID, []loadbalancer.Backend, loadbalancer.SVCType, string, string) (bool, loadbalancer.ID, error) was called and is not set!")
}

func (s *K8sWatcherSuite) TestUpdateToServiceEndpointsGH9525(c *C) {

	ep1stApply := &types.Endpoints{
		Endpoints: &v1.Endpoints{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "bar",
			},
			Subsets: []v1.EndpointSubset{
				{
					Addresses: []v1.EndpointAddress{{IP: "2.2.2.2"}},
					Ports: []v1.EndpointPort{
						{
							Name:     "http-test-svc",
							Port:     8080,
							Protocol: v1.ProtocolTCP,
						},
					},
				},
			},
		},
	}

	ep2ndApply := ep1stApply.DeepCopy()
	ep2ndApply.Subsets[0].Addresses = append(
		ep2ndApply.Subsets[0].Addresses,
		v1.EndpointAddress{IP: "3.3.3.3"},
	)

	policyManagerCalls := 0
	policyManager := &fakePolicyManager{
		OnTriggerPolicyUpdates: func(force bool, reason string) {
			policyManagerCalls++
		},
	}
	policyRepositoryCalls := 0
	policyRepository := &fakePolicyRepository{
		OnTranslateRules: func(tr policy.Translator) (result *policy.TranslationResult, e error) {
			rt, ok := tr.(k8s.RuleTranslator)
			c.Assert(ok, Equals, true)
			switch policyRepositoryCalls {
			case 0:
				_, parsedEPs := k8s.ParseEndpoints(ep1stApply)
				c.Assert(rt.Endpoint.Backends, checker.DeepEquals, parsedEPs.Backends)
			case 1:
				_, parsedEPs := k8s.ParseEndpoints(ep2ndApply)
				c.Assert(rt.Endpoint.Backends, checker.DeepEquals, parsedEPs.Backends)
			default:
				c.Assert(policyRepositoryCalls, Not(Equals), 0, Commentf("policy repository was called more times than expected!"))
			}
			policyRepositoryCalls++

			return &policy.TranslationResult{NumToServicesRules: 1}, nil
		},
	}

	w := NewK8sWatcher(
		nil,
		nil,
		policyManager,
		policyRepository,
		nil,
	)
	go w.k8sServiceHandler()
	swg := lock.NewStoppableWaitGroup()

	k8sSvc := &types.Service{
		Service: &v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "foo",
				Namespace: "bar",
				Labels: map[string]string{
					"foo": "bar",
				},
			},
			Spec: v1.ServiceSpec{
				ClusterIP: "127.0.0.1",
				Type:      v1.ServiceTypeClusterIP,
			},
		},
	}

	w.K8sSvcCache.UpdateService(k8sSvc, swg)
	w.K8sSvcCache.UpdateEndpoints(ep1stApply, swg)
	// Running a 2nd update should also trigger a new policy update
	w.K8sSvcCache.UpdateEndpoints(ep2ndApply, swg)

	swg.Stop()
	swg.Wait()

	c.Assert(policyRepositoryCalls, Equals, 2)
	c.Assert(policyManagerCalls, Equals, 2)
}
