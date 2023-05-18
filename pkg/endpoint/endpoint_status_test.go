// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"fmt"
	"reflect"
	"time"

	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/identity"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
)

var (
	allowAllIdentityList = cilium_v2.AllowedIdentityList{{}}
	denyAllIdentityList  = cilium_v2.AllowedIdentityList(nil)
)

type endpointGeneratorSpec struct {
	failingControllers       int
	logErrors                int
	allowedIngressIdentities int
	allowedEgressIdentities  int
	numPortsPerIdentity      int
	fakeControllerManager    bool
}

type endpointStatusConfiguration map[string]bool

func (e endpointStatusConfiguration) EndpointStatusIsEnabled(name string) bool {
	if e != nil {
		return e[string(name)]
	}
	return false
}

func (s *EndpointSuite) newEndpoint(c *check.C, spec endpointGeneratorSpec) *Endpoint {
	e, err := NewEndpointFromChangeModel(context.TODO(), s, s, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, s.mgr, &models.EndpointChangeRequest{
		Addressing: &models.AddressPair{},
		ID:         200,
		Labels: models.Labels{
			"k8s:io.cilium.k8s.policy.cluster=default",
			"k8s:io.cilium.k8s.policy.serviceaccount=default",
			"k8s:io.kubernetes.pod.namespace=default",
			"k8s:name=probe",
		},
		State: models.EndpointStateWaitingDashForDashIdentity.Pointer(),
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
		e.status.addStatusLog(&statusLogMsg{
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
	e := s.newEndpoint(c, endpointGeneratorSpec{})
	cepA := e.GetCiliumEndpointStatus(&endpointStatusConfiguration{})

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
			cepB := e.GetCiliumEndpointStatus(&endpointStatusConfiguration{})
			c.Assert(cepA, checker.DeepEquals, cepB)
		}
	}
}

func (s *EndpointSuite) TestGetCiliumEndpointStatusSuccessfulLog(c *check.C) {
	e := s.newEndpoint(c, endpointGeneratorSpec{})
	cepA := e.GetCiliumEndpointStatus(&endpointStatusConfiguration{})

	go func() {
		for i := 0; i < 1000; i++ {
			e.status.addStatusLog(&statusLogMsg{
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
			cepB := e.GetCiliumEndpointStatus(&endpointStatusConfiguration{})
			c.Assert(cepA, checker.DeepEquals, cepB)
		}
	}
}

func (s *EndpointSuite) TestGetCiliumEndpointStatusDeepEqual(c *check.C) {
	a := s.newEndpoint(c, endpointGeneratorSpec{
		fakeControllerManager:    true,
		failingControllers:       10,
		logErrors:                maxLogs,
		allowedIngressIdentities: 100,
		allowedEgressIdentities:  100,
		numPortsPerIdentity:      10,
	})

	b := s.newEndpoint(c, endpointGeneratorSpec{
		fakeControllerManager:    true,
		failingControllers:       10,
		logErrors:                maxLogs,
		allowedIngressIdentities: 100,
		allowedEgressIdentities:  100,
		numPortsPerIdentity:      10,
	})

	cepA := a.GetCiliumEndpointStatus(&endpointStatusConfiguration{})
	cepB := b.GetCiliumEndpointStatus(&endpointStatusConfiguration{})

	c.Assert(cepA, checker.DeepEquals, cepB)
}

func (s *EndpointSuite) TestGetCiliumEndpointStatusCorrectnes(c *check.C) {
	e := s.newEndpoint(c, endpointGeneratorSpec{
		fakeControllerManager:    true,
		failingControllers:       10,
		logErrors:                maxLogs,
		allowedIngressIdentities: 100,
		allowedEgressIdentities:  100,
		numPortsPerIdentity:      10,
	})

	cep := e.GetCiliumEndpointStatus(&endpointStatusConfiguration{
		option.EndpointStatusLog: true,
	})

	c.Assert(len(cep.Log), check.Equals, cilium_v2.EndpointStatusLogEntries)
}

// apiResult is an individual desired AllowedIdentityEntry test result entry.
type apiResult struct {
	labels   string
	identity uint64
	dport    uint16
	proto    uint8
}

func prepareExpectedList(want []apiResult) cilium_v2.AllowedIdentityList {
	expectedList := denyAllIdentityList
	if want != nil {
		expectedList = cilium_v2.AllowedIdentityList{}
		for _, w := range want {
			entry := cilium_v2.IdentityTuple{
				Identity: w.identity,
				DestPort: w.dport,
				Protocol: w.proto,
			}
			if w.labels != "" {
				entry.IdentityLabels = map[string]string{
					w.labels: "",
				}
			}
			expectedList = append(expectedList, entry)
		}
		expectedList.Sort()
	}

	return expectedList
}

func (s *EndpointSuite) TestgetEndpointPolicyMapState(c *check.C) {
	e := s.newEndpoint(c, endpointGeneratorSpec{
		fakeControllerManager:    true,
		failingControllers:       10,
		logErrors:                maxLogs,
		allowedIngressIdentities: 100,
		allowedEgressIdentities:  100,
		numPortsPerIdentity:      10,
	})
	// Policy not enabled; allow all.
	apiPolicy := e.getEndpointPolicy()
	c.Assert(apiPolicy.Ingress.Allowed, checker.DeepEquals, allowAllIdentityList)
	c.Assert(apiPolicy.Egress.Allowed, checker.DeepEquals, allowAllIdentityList)

	fooLbls := labels.Labels{"": labels.ParseLabel("foo")}
	fooIdentity, _, err := e.allocator.AllocateIdentity(context.Background(), fooLbls, false, identity.InvalidIdentity)
	c.Assert(err, check.Equals, nil)
	defer s.mgr.Release(context.Background(), fooIdentity, false)

	e.desiredPolicy = policy.NewEndpointPolicy(s.repo)
	e.desiredPolicy.IngressPolicyEnabled = true
	e.desiredPolicy.EgressPolicyEnabled = true

	type args struct {
		identity  uint32
		destPort  uint16
		nexthdr   uint8
		direction trafficdirection.TrafficDirection
	}

	tests := []struct {
		name          string
		args          []args
		egressResult  []apiResult
		ingressResult []apiResult
	}{
		{
			name: "Deny all",
		},
		{
			name: "Allow all ingress",
			args: []args{
				{0, 0, 0, trafficdirection.Ingress},
			},
			ingressResult: []apiResult{{}},
			egressResult:  nil,
		},
		{
			name: "Allow all egress",
			args: []args{
				{0, 0, 0, trafficdirection.Egress},
			},
			ingressResult: nil,
			egressResult:  []apiResult{{}},
		},
		{
			name: "Allow all both directions",
			args: []args{
				{0, 0, 0, trafficdirection.Ingress},
				{0, 0, 0, trafficdirection.Egress},
			},
			ingressResult: []apiResult{{}},
			egressResult:  []apiResult{{}},
		},
		{
			name: "Allow world ingress",
			args: []args{
				{uint32(identity.ReservedIdentityWorld), 0, 0, trafficdirection.Ingress},
			},
			ingressResult: []apiResult{
				{"reserved:world", uint64(identity.ReservedIdentityWorld), 0, 0},
			},
			egressResult: nil,
		},
		{
			name: "Allow world egress",
			args: []args{
				{uint32(identity.ReservedIdentityWorld), 0, 0, trafficdirection.Egress},
			},
			ingressResult: nil,
			egressResult: []apiResult{
				{"reserved:world", uint64(identity.ReservedIdentityWorld), 0, 0},
			},
		},
		{
			name: "Allow world both directions",
			args: []args{
				{uint32(identity.ReservedIdentityWorld), 0, 0, trafficdirection.Ingress},
				{uint32(identity.ReservedIdentityWorld), 0, 0, trafficdirection.Egress},
			},
			ingressResult: []apiResult{
				{"reserved:world", uint64(identity.ReservedIdentityWorld), 0, 0},
			},
			egressResult: []apiResult{
				{"reserved:world", uint64(identity.ReservedIdentityWorld), 0, 0},
			},
		},
		{
			name: "Ingress mix of L3, L4, L3-dependent L4",
			args: []args{
				{uint32(fooIdentity.ID), 0, 0, trafficdirection.Ingress},  // L3-only map state
				{0, 80, 6, trafficdirection.Ingress},                      // L4-only map state
				{uint32(fooIdentity.ID), 80, 6, trafficdirection.Ingress}, // L3-dependent L4 map state
			},
			ingressResult: []apiResult{
				{"unspec:foo", uint64(fooIdentity.ID), 0, 0},
				{"", 0, 80, 6},
				{"unspec:foo", uint64(fooIdentity.ID), 80, 6},
			},
			egressResult: nil,
		},
		{
			name: "Egress mix of L3, L4, L3-dependent L4",
			args: []args{
				{uint32(fooIdentity.ID), 0, 0, trafficdirection.Egress},  // L3-only map state
				{0, 80, 6, trafficdirection.Egress},                      // L4-only map state
				{uint32(fooIdentity.ID), 80, 6, trafficdirection.Egress}, // L3-dependent L4 map state
			},
			ingressResult: nil,
			egressResult: []apiResult{
				{"unspec:foo", uint64(fooIdentity.ID), 0, 0},
				{"", 0, 80, 6},
				{"unspec:foo", uint64(fooIdentity.ID), 80, 6},
			},
		},
		{
			name: "World shadows CIDR ingress",
			args: []args{
				{uint32(identity.ReservedIdentityWorld), 0, 0, trafficdirection.Ingress},
				{uint32(identity.LocalIdentityFlag), 0, 0, trafficdirection.Ingress},
			},
			ingressResult: []apiResult{
				{"reserved:world", uint64(identity.ReservedIdentityWorld), 0, 0},
			},
			egressResult: nil,
		},
		{
			name: "World shadows CIDR egress",
			args: []args{
				{uint32(identity.ReservedIdentityWorld), 0, 0, trafficdirection.Egress},
				{uint32(identity.LocalIdentityFlag), 0, 0, trafficdirection.Egress},
			},
			ingressResult: nil,
			egressResult: []apiResult{
				{"reserved:world", uint64(identity.ReservedIdentityWorld), 0, 0},
			},
		},
	}

	for _, tt := range tests {
		e.desiredPolicy.PolicyMapState = policy.MapState{}
		for _, arg := range tt.args {
			t := policy.Key{
				Identity:         arg.identity,
				DestPort:         arg.destPort,
				Nexthdr:          arg.nexthdr,
				TrafficDirection: arg.direction.Uint8(),
			}
			e.desiredPolicy.PolicyMapState[t] = policy.MapStateEntry{}
		}
		expectedIngressList := prepareExpectedList(tt.ingressResult)
		expectedEgressList := prepareExpectedList(tt.egressResult)

		apiPolicy = e.getEndpointPolicy()
		c.Assert(apiPolicy.Ingress.Allowed, checker.DeepEquals, expectedIngressList)
		c.Assert(apiPolicy.Egress.Allowed, checker.DeepEquals, expectedEgressList)
	}
}

func (s *EndpointSuite) TestEndpointPolicyStatus(c *check.C) {
	tcs := []struct {
		ingressEnabled bool
		egressEnabled  bool
		auditEnabled   bool
		status         models.EndpointPolicyEnabled
	}{
		{false, false, false, models.EndpointPolicyEnabledNone},
		{true, false, false, models.EndpointPolicyEnabledIngress},
		{false, true, false, models.EndpointPolicyEnabledEgress},
		{true, true, false, models.EndpointPolicyEnabledBoth},
		{false, false, true, models.EndpointPolicyEnabledNone},
		{true, false, true, models.EndpointPolicyEnabledAuditDashIngress},
		{false, true, true, models.EndpointPolicyEnabledAuditDashEgress},
		{true, true, true, models.EndpointPolicyEnabledAuditDashBoth},
	}

	e := s.newEndpoint(c, endpointGeneratorSpec{})
	for _, tc := range tcs {
		e.realizedPolicy.IngressPolicyEnabled = tc.ingressEnabled
		e.realizedPolicy.EgressPolicyEnabled = tc.egressEnabled
		e.Options.SetBool(option.PolicyAuditMode, tc.auditEnabled)
		c.Assert(e.policyStatus(), checker.Equals, tc.status)
	}
}

func (s *EndpointSuite) TestEndpointPolicy(c *check.C) {
	tcs := []struct {
		ingressEnabled   bool
		egressEnabled    bool
		auditEnabled     bool
		ingressEnforcing bool
		egressEnforcing  bool
	}{
		{false, false, false, false, false},
		{true, false, false, true, false},
		{false, true, false, false, true},
		{true, true, false, true, true},
		{false, false, true, false, false},
		{true, false, true, false, false},
		{false, true, true, false, false},
		{true, true, true, false, false},
	}

	e := s.newEndpoint(c, endpointGeneratorSpec{})
	for _, tc := range tcs {
		e.desiredPolicy.IngressPolicyEnabled = tc.ingressEnabled
		e.desiredPolicy.EgressPolicyEnabled = tc.egressEnabled
		e.Options.SetBool(option.PolicyAuditMode, tc.auditEnabled)
		policy := e.getEndpointPolicy()
		c.Assert(policy.Ingress.Enforcing, checker.Equals, tc.ingressEnforcing)
		c.Assert(policy.Egress.Enforcing, checker.Equals, tc.egressEnforcing)
	}
}

func (s *EndpointSuite) BenchmarkGetCiliumEndpointStatusDeepEqual(c *check.C) {
	a := s.newEndpoint(c, endpointGeneratorSpec{
		fakeControllerManager:    true,
		failingControllers:       10,
		logErrors:                maxLogs,
		allowedIngressIdentities: 100,
		allowedEgressIdentities:  100,
		numPortsPerIdentity:      10,
	})

	b := s.newEndpoint(c, endpointGeneratorSpec{
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
	e := s.newEndpoint(c, endpointGeneratorSpec{
		failingControllers:       10,
		logErrors:                maxLogs,
		allowedIngressIdentities: 100,
		allowedEgressIdentities:  100,
		numPortsPerIdentity:      10,
	})

	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		status := e.GetCiliumEndpointStatus(&endpointStatusConfiguration{})
		c.Assert(status, check.Not(check.IsNil))
	}
	c.StopTimer()
}
