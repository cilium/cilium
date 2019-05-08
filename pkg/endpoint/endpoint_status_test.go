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

package endpoint

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"

	"gopkg.in/check.v1"
)

type endpointGeneratorSpec struct {
	failingControllers       int
	logErrors                int
	allowedIngressIdentities int
	allowedEgressIdentities  int
	numPortsPerIdentity      int
	fakeControllerManager    bool
}

func newEndpoint(c *check.C, spec endpointGeneratorSpec) *Endpoint {
	e, err := NewEndpointFromChangeModel(&models.EndpointChangeRequest{
		Addressing: &models.AddressPair{},
		ID:         200,
		Labels: models.Labels{
			"k8s:io.cilium.k8s.policy.cluster=default",
			"k8s:io.cilium.k8s.policy.serviceaccount=default",
			"k8s:io.kubernetes.pod.namespace=default",
			"k8s:name=probe",
		},
		State: models.EndpointState("waiting-for-identity"),
	})
	c.Assert(err, check.IsNil)

	e.SecurityIdentity = &identity.Identity{
		ID: 100,
		Labels: labels.NewLabelsFromModel([]string{
			"k8s:io.cilium.k8s.policy.cluster=default",
			"k8s:io.cilium.k8s.policy.serviceaccount=default",
			"k8s:io.kubernetes.pod.namespace=default",
			"k8s:name=probe",
		}),
	}

	if spec.fakeControllerManager {
		e.controllers = controller.FakeManager(spec.failingControllers)
	}

	for i := 0; i < spec.logErrors; i++ {
		e.Status.addStatusLog(&statusLogMsg{
			Status: Status{Code: Failure, Msg: "Failure", Type: BPF},
		})
	}

	e.desiredPolicy.PolicyMapState = policy.MapState{}

	if spec.numPortsPerIdentity == 0 {
		spec.numPortsPerIdentity = 1
	}

	for i := 0; i < spec.allowedIngressIdentities; i++ {
		for n := 0; n < spec.numPortsPerIdentity; n++ {
			key := policy.Key{
				Identity:         uint32(i),
				DestPort:         uint16(80 + n),
				TrafficDirection: trafficdirection.Ingress.Uint8(),
			}
			e.desiredPolicy.PolicyMapState[key] = policy.MapStateEntry{}
		}
	}

	for i := 0; i < spec.allowedIngressIdentities; i++ {
		for n := 0; n < spec.numPortsPerIdentity; n++ {
			key := policy.Key{
				Identity:         uint32(i + 30000),
				DestPort:         uint16(80 + n),
				TrafficDirection: trafficdirection.Egress.Uint8(),
			}
			e.desiredPolicy.PolicyMapState[key] = policy.MapStateEntry{}
		}
	}

	return e
}

func (s *EndpointSuite) TestGetCiliumEndpointStatusSuccessfulControllers(c *check.C) {
	e := newEndpoint(c, endpointGeneratorSpec{})
	cepA := e.GetCiliumEndpointStatus()

	// Run successful controllers in the background
	for i := 0; i < 50; i++ {
		e.controllers.UpdateController(fmt.Sprintf("controller-%d", i),
			controller.ControllerParams{
				DoFunc: func(ctx context.Context) error {
					return nil
				},
				RunInterval: 10 * time.Millisecond,
			},
		)
	}
	defer e.controllers.RemoveAll()

	// Generate EndpointStatus in quick interval while controllers are
	// succeeding in the background
	timeout := time.After(1 * time.Second)
	tick := time.Tick(10 * time.Millisecond)
	for {
		select {
		case <-timeout:
			return
		case <-tick:
			cepB := e.GetCiliumEndpointStatus()
			c.Assert(cepA, checker.DeepEquals, cepB)
		}
	}
}

func (s *EndpointSuite) TestGetCiliumEndpointStatusSuccessfulLog(c *check.C) {
	e := newEndpoint(c, endpointGeneratorSpec{})
	cepA := e.GetCiliumEndpointStatus()

	go func() {
		for i := 0; i < 1000; i++ {
			e.Status.addStatusLog(&statusLogMsg{
				Status: Status{Code: OK, Msg: "Success", Type: BPF},
			})
			time.Sleep(time.Millisecond)
		}
	}()

	// Generate EndpointStatus in quick interval while state transitions
	// are succeeding in the background
	timeout := time.After(1 * time.Second)
	tick := time.Tick(10 * time.Millisecond)
	for {
		select {
		case <-timeout:
			return
		case <-tick:
			cepB := e.GetCiliumEndpointStatus()
			c.Assert(cepA, checker.DeepEquals, cepB)
		}
	}
}

func (s *EndpointSuite) TestGetCiliumEndpointStatusDeepEqual(c *check.C) {
	a := newEndpoint(c, endpointGeneratorSpec{
		fakeControllerManager:    true,
		failingControllers:       10,
		logErrors:                maxLogs,
		allowedIngressIdentities: 100,
		allowedEgressIdentities:  100,
		numPortsPerIdentity:      10,
	})

	b := newEndpoint(c, endpointGeneratorSpec{
		fakeControllerManager:    true,
		failingControllers:       10,
		logErrors:                maxLogs,
		allowedIngressIdentities: 100,
		allowedEgressIdentities:  100,
		numPortsPerIdentity:      10,
	})

	cepA := a.GetCiliumEndpointStatus()
	cepB := b.GetCiliumEndpointStatus()

	c.Assert(cepA, checker.DeepEquals, cepB)
}

func (s *EndpointSuite) TestGetCiliumEndpointStatusCorrectnes(c *check.C) {
	e := newEndpoint(c, endpointGeneratorSpec{
		fakeControllerManager:    true,
		failingControllers:       10,
		logErrors:                maxLogs,
		allowedIngressIdentities: 100,
		allowedEgressIdentities:  100,
		numPortsPerIdentity:      10,
	})

	cep := e.GetCiliumEndpointStatus()

	c.Assert(len(cep.Status.Log), check.Equals, cilium_v2.EndpointStatusLogEntries)
}

func (s *EndpointSuite) TestgetEndpointPolicyMapState(c *check.C) {
	e := newEndpoint(c, endpointGeneratorSpec{
		fakeControllerManager:    true,
		failingControllers:       10,
		logErrors:                maxLogs,
		allowedIngressIdentities: 100,
		allowedEgressIdentities:  100,
		numPortsPerIdentity:      10,
	})
	// Policy not enabled; allow all.
	apiPolicy := e.getEndpointPolicy()
	c.Assert(apiPolicy.Ingress.Allowed, checker.DeepEquals, cilium_v2.AllowedIdentityList(nil))
	c.Assert(apiPolicy.Egress.Allowed, checker.DeepEquals, cilium_v2.AllowedIdentityList(nil))

	fooLbls := labels.Labels{"": labels.ParseLabel("foo")}
	fooIdentity, _, err := cache.AllocateIdentity(nil, context.Background(), fooLbls)
	c.Assert(err, check.Equals, nil)
	defer cache.Release(nil, context.Background(), fooIdentity)

	e.desiredPolicy = &policy.EndpointPolicy{
		PolicyMapState: policy.MapState{
			// L3-only map state
			{
				Identity: uint32(fooIdentity.ID),
				DestPort: 0,
				Nexthdr:  0,
			}: {},
			// L4-only map state
			{
				Identity: 0,
				DestPort: 80,
				Nexthdr:  6,
			}: {},
			// L3-dependent L4 map state
			{
				Identity: uint32(fooIdentity.ID),
				DestPort: 80,
				Nexthdr:  6,
			}: {},
		},
		SelectorPolicy: &policy.SelectorPolicy{
			IngressPolicyEnabled: true,
			EgressPolicyEnabled:  true,
		},
	}

	apiPolicy = e.getEndpointPolicy()
	expectedIdentityList := cilium_v2.AllowedIdentityList{
		{
			Identity: uint64(fooIdentity.ID),
			IdentityLabels: map[string]string{
				"unspec:foo": "",
			},
		},
		{
			Identity:       0,
			DestPort:       80,
			Protocol:       6,
			IdentityLabels: map[string]string(nil),
		},
		{
			Identity: uint64(fooIdentity.ID),
			DestPort: 80,
			Protocol: 6,
			IdentityLabels: map[string]string{
				"unspec:foo": "",
			},
		},
	}
	expectedIdentityList.Sort()
	c.Assert(apiPolicy.Ingress.Allowed, checker.DeepEquals, expectedIdentityList)
	c.Assert(apiPolicy.Egress.Allowed, checker.DeepEquals, cilium_v2.AllowedIdentityList(nil))
}

func (s *EndpointSuite) BenchmarkGetCiliumEndpointStatusDeepEqual(c *check.C) {
	a := newEndpoint(c, endpointGeneratorSpec{
		fakeControllerManager:    true,
		failingControllers:       10,
		logErrors:                maxLogs,
		allowedIngressIdentities: 100,
		allowedEgressIdentities:  100,
		numPortsPerIdentity:      10,
	})

	b := newEndpoint(c, endpointGeneratorSpec{
		fakeControllerManager:    true,
		failingControllers:       10,
		logErrors:                maxLogs,
		allowedIngressIdentities: 100,
		allowedEgressIdentities:  100,
		numPortsPerIdentity:      10,
	})

	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		if !reflect.DeepEqual(a, b) {
			c.Errorf("DeepEqual failed")
		}
	}
	c.StopTimer()
}

func (s *EndpointSuite) BenchmarkGetCiliumEndpointStatus(c *check.C) {
	e := newEndpoint(c, endpointGeneratorSpec{
		failingControllers:       10,
		logErrors:                maxLogs,
		allowedIngressIdentities: 100,
		allowedEgressIdentities:  100,
		numPortsPerIdentity:      10,
	})

	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		status := e.GetCiliumEndpointStatus()
		c.Assert(status, check.Not(check.IsNil))
	}
	c.StopTimer()
}
