// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"testing"

	. "github.com/cilium/checkmate"

	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type K8sWatcherSuite struct{}

var _ = Suite(&K8sWatcherSuite{})

var emptyResources = agentK8s.Resources{}

type fakeWatcherConfiguration struct{}

func (f *fakeWatcherConfiguration) K8sNetworkPolicyEnabled() bool {
	return true
}

type fakePolicyManager struct {
	OnTriggerPolicyUpdates func(force bool, reason string)
	OnPolicyAdd            func(rules api.Rules, opts *policy.AddOptions) (newRev uint64, err error)
	OnPolicyDelete         func(labels labels.LabelArray, opts *policy.DeleteOptions) (newRev uint64, err error)
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

func (f *fakePolicyManager) PolicyDelete(labels labels.LabelArray, opts *policy.DeleteOptions) (newRev uint64, err error) {
	if f.OnPolicyDelete != nil {
		return f.OnPolicyDelete(labels, opts)
	}
	panic("OnPolicyDelete(labels.LabelArray, *policy.DeleteOptions) (uint64, error) was called and is not set!")
}

type fakePolicyRepository struct {
	OnGetSelectorCache func() *policy.SelectorCache
}

func (f *fakePolicyRepository) GetSelectorCache() *policy.SelectorCache {
	if f.OnGetSelectorCache != nil {
		return f.OnGetSelectorCache()
	}
	panic("OnGetSelectorCache() (*policy.SelectorCache) was called and is not set!")
}

type fakeSvcManager struct {
	OnDeleteService func(frontend loadbalancer.L3n4Addr) (bool, error)
	OnUpsertService func(*loadbalancer.SVC) (bool, loadbalancer.ID, error)
}

func (f *fakeSvcManager) DeleteService(frontend loadbalancer.L3n4Addr) (bool, error) {
	if f.OnDeleteService != nil {
		return f.OnDeleteService(frontend)
	}
	panic("OnDeleteService(loadbalancer.L3n4Addr) (bool, error) was called and is not set!")
}

func (f *fakeSvcManager) GetDeepCopyServiceByFrontend(frontend loadbalancer.L3n4Addr) (*loadbalancer.SVC, bool) {
	return nil, false
}

func (f *fakeSvcManager) UpsertService(p *loadbalancer.SVC) (bool, loadbalancer.ID, error) {
	if f.OnUpsertService != nil {
		return f.OnUpsertService(p)
	}
	panic("OnUpsertService() was called and is not set!")
}
