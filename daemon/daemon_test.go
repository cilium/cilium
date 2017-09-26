// Copyright 2016-2017 Authors of Cilium
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

package main

import (
	"runtime"
	"testing"

	e "github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type DaemonSuite struct {
	d *Daemon

	// Owners interface mock
	OnTracingEnabled                  func() bool
	OnDryModeEnabled                  func() bool
	OnEnableEndpointPolicyEnforcement func(e *e.Endpoint) bool
	OnPolicyEnforcement               func() string
	OnAlwaysAllowLocalhost            func() bool
	OnGetCachedLabelList              func(id policy.NumericIdentity) (labels.LabelArray, error)
	OnGetPolicyRepository             func() *policy.Repository
	OnGetCachedMaxLabelID             func() (policy.NumericIdentity, error)
	OnUpdateProxyRedirect             func(e *e.Endpoint, l4 *policy.L4Filter) (uint16, error)
	OnRemoveProxyRedirect             func(e *e.Endpoint, l4 *policy.L4Filter) error
	OnGetStateDir                     func() string
	OnGetBpfDir                       func() string
	OnQueueEndpointBuild              func(r *e.Request)
	OnRemoveFromEndpointQueue         func(epID uint64)
	OnDebugEnabled                    func() bool
	OnAnnotateEndpoint                func(e *e.Endpoint, annotationKey, annotationValue string)
	OnGetCompilationLock              func() *lock.RWMutex
}

var _ = Suite(&DaemonSuite{})

func (ds *DaemonSuite) TestMiniumWorkerThreadsIsSet(c *C) {
	c.Assert(numWorkerThreads() >= 4, Equals, true)
	c.Assert(numWorkerThreads() >= runtime.NumCPU(), Equals, true)
}

func (ds *DaemonSuite) TracingEnabled() bool {
	if ds.OnTracingEnabled != nil {
		return ds.OnTracingEnabled()
	}
	panic("TracingEnabled should not have been called")
}

func (ds *DaemonSuite) DryModeEnabled() bool {
	if ds.OnDryModeEnabled != nil {
		return ds.OnDryModeEnabled()
	}
	panic("DryModeEnabled should not have been called")
}

func (ds *DaemonSuite) AnnotateEndpoint(e *e.Endpoint, annotationKey, annotationValue string) {
	if ds.OnAnnotateEndpoint != nil {
		ds.OnAnnotateEndpoint(e, annotationKey, annotationValue)
	}
	panic("OnAnnotateEndpoint should not have been called")

}

func (ds *DaemonSuite) EnableEndpointPolicyEnforcement(e *e.Endpoint) bool {
	if ds.OnEnableEndpointPolicyEnforcement != nil {
		return ds.OnEnableEndpointPolicyEnforcement(e)
	}
	panic("UpdateEndpointPolicyEnforcement should not have been called")
}

func (ds *DaemonSuite) PolicyEnforcement() string {
	if ds.OnPolicyEnforcement != nil {
		return ds.OnPolicyEnforcement()
	}
	panic("PolicyEnforcement should not have been called")
}

func (ds *DaemonSuite) AlwaysAllowLocalhost() bool {
	if ds.OnAlwaysAllowLocalhost != nil {
		return ds.OnAlwaysAllowLocalhost()
	}
	panic("AlwaysAllowLocalhost should not have been called")
}

func (ds *DaemonSuite) GetCachedLabelList(id policy.NumericIdentity) (labels.LabelArray, error) {
	if ds.OnGetCachedLabelList != nil {
		return ds.OnGetCachedLabelList(id)
	}
	panic("GetCachedLabelList should not have been called")
}

func (ds *DaemonSuite) GetPolicyRepository() *policy.Repository {
	if ds.OnGetPolicyRepository != nil {
		return ds.OnGetPolicyRepository()
	}
	panic("GetPolicyRepository should not have been called")
}

func (ds *DaemonSuite) GetCachedMaxLabelID() (policy.NumericIdentity, error) {
	if ds.OnGetCachedMaxLabelID != nil {
		return ds.OnGetCachedMaxLabelID()
	}
	panic("GetCachedMaxLabelID should not have been called")
}

func (ds *DaemonSuite) UpdateProxyRedirect(e *e.Endpoint, l4 *policy.L4Filter) (uint16, error) {
	if ds.OnUpdateProxyRedirect != nil {
		return ds.OnUpdateProxyRedirect(e, l4)
	}
	panic("UpdateProxyRedirect should not have been called")
}

func (ds *DaemonSuite) RemoveProxyRedirect(e *e.Endpoint, l4 *policy.L4Filter) error {
	if ds.OnRemoveProxyRedirect != nil {
		return ds.OnRemoveProxyRedirect(e, l4)
	}
	panic("RemoveProxyRedirect should not have been called")
}

func (ds *DaemonSuite) GetStateDir() string {
	if ds.OnGetStateDir != nil {
		return ds.OnGetStateDir()
	}
	panic("GetStateDir should not have been called")
}

func (ds *DaemonSuite) GetBpfDir() string {
	if ds.OnGetBpfDir != nil {
		return ds.OnGetBpfDir()
	}
	panic("GetBpfDir should not have been called")
}

func (ds *DaemonSuite) QueueEndpointBuild(r *e.Request) {
	if ds.OnQueueEndpointBuild != nil {
		ds.OnQueueEndpointBuild(r)
		return
	}
	panic("QueueEndpointBuild should not have been called")
}

func (ds *DaemonSuite) RemoveFromEndpointQueue(epID uint64) {
	if ds.OnRemoveFromEndpointQueue != nil {
		ds.OnRemoveFromEndpointQueue(epID)
		return
	}
	panic("RemoveFromEndpointQueue should not have been called")
}

func (ds *DaemonSuite) DebugEnabled() bool {
	if ds.OnDebugEnabled != nil {
		return ds.OnDebugEnabled()
	}
	panic("DebugEnabled should not have been called")
}

func (ds *DaemonSuite) GetCompilationLock() *lock.RWMutex {
	if ds.OnGetCompilationLock != nil {
		return ds.OnGetCompilationLock()
	}
	panic("GetCompilationLock should not have been called")
}
