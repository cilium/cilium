// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	testk8s "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	policyutils "github.com/cilium/cilium/pkg/policy/utils"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

func appLabels(app string) labels.Labels {
	return labels.NewLabelsFromModel([]string{
		"k8s:io.kubernetes.pod.namespace=default",
		"k8s:app=" + app,
	})
}

// regenFixture is a testFixture for tests that drive endpoint regenerations
// directly.
type regenFixture struct {
	*testFixture
	ctx context.Context
}

func newRegenFixture(t *testing.T) *regenFixture {
	// Only check for the goroutines this test leaks, not ones an earlier failed
	// test left behind.
	current := testutils.GoleakIgnoreCurrent()
	t.Cleanup(func() {
		testutils.GoleakVerifyNone(t, current,
			testutils.GoleakIgnoreAnyFunction("github.com/cilium/cilium/pkg/trigger.(*Trigger).waiter"),
			testutils.GoleakIgnoreAnyFunction("github.com/cilium/cilium/pkg/policy.(*SelectorCache).handleUserNotifications"),
		)
	})
	version.Force(testk8s.DefaultVersion)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	return &regenFixture{testFixture: newTestFixture(t, hivetest.Logger(t), nil), ctx: ctx}
}

// localIdentity allocates the identity for lbls and makes it local without an
// endpoint, so that its selector policy is computed.
func (f *regenFixture) localIdentity(t *testing.T, lbls labels.Labels) *identity.Identity {
	id, _, err := f.allocator.AllocateIdentity(f.ctx, lbls, true, identity.InvalidIdentity)
	require.NoError(t, err)
	f.idmgr.Add(id)
	t.Cleanup(func() { f.idmgr.Remove(id) })
	require.Eventually(t, func() bool {
		_, _, _, found := f.computer.GetIdentityPolicyByIdentity(id)
		return found
	}, 5*time.Second, time.Millisecond)
	return id
}

// importSelecting imports a rule selecting app and waits until the import,
// including the endpoint updates it triggers, has completed.
func (f *regenFixture) importSelecting(t *testing.T, name, app string) {
	f.importRules(t, name, selecting(t, name, app))
	f.barrier(t)
}

// barrier waits until all earlier imports, including the endpoint updates they
// trigger, have completed. An import is reported done before the endpoints are
// updated, but imports are processed in order.
func (f *regenFixture) barrier(t *testing.T) {
	f.importRules(t, "barrier", nil)
}

// importRules imports rules and waits until the import is reported done.
func (f *regenFixture) importRules(t *testing.T, name string, rules api.Rules) {
	done := make(chan uint64, 1)
	f.importer.UpdatePolicy(policyUpdate(name, rules, done))
	f.receive(t, done)
}

func (f *regenFixture) receive(t *testing.T, done <-chan uint64) uint64 {
	select {
	case rev := <-done:
		return rev
	case <-f.ctx.Done():
		t.Fatal("policy import timed out")
		return 0
	}
}

func policyUpdate(name string, rules api.Rules, done chan uint64) *policytypes.PolicyUpdate {
	return &policytypes.PolicyUpdate{
		Rules:    policyutils.RulesToPolicyEntries(rules),
		Source:   source.CustomResource,
		Resource: ipcachetypes.NewResourceID(ipcachetypes.ResourceKindCNP, "default", name),
		DoneChan: done,
	}
}

// selecting returns a rule named name that selects app.
func selecting(t *testing.T, name, app string) api.Rules {
	rule := &api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.NewLabel("app", app, labels.LabelSourceK8s)),
		Egress: []api.EgressRule{{
			ToPorts: []api.PortRule{{
				Ports: []api.PortProtocol{{Port: "80", Protocol: "TCP"}},
			}},
		}},
		Labels: labels.LabelArray{labels.NewLabel(k8sConst.PolicyLabelName, name, labels.LabelSourceAny)},
	}
	require.NoError(t, rule.ValidateAndSanitize())
	return api.Rules{rule}
}

// addEndpoint adds an endpoint with lbls from the fixture's template, without
// waiting for it to regenerate.
func (f *regenFixture) addEndpoint(t *testing.T, lbls labels.Labels) *endpoint.Endpoint {
	ep := f.templateEP.CopyFromTemplate()
	require.NoError(t, f.epm.AddEndpoint(ep))
	_ = ep.UpdateLabels(f.ctx, labels.LabelSourceAny, lbls, nil, true)
	return ep
}

// createEndpoint creates an endpoint from the fixture's template the way the
// agent does, and waits for its first regeneration.
func (f *regenFixture) createEndpoint(t *testing.T, lbls labels.Labels) *endpoint.Endpoint {
	ep := f.addEndpoint(t, lbls)
	// Use RegenerateIfAlive to set the endpoint state to WaitingToRegenerate.
	_ = ep.RegenerateIfAlive(&regeneration.ExternalRegenerationMetadata{
		Reason:            "simulate Orchestrator",
		RegenerationLevel: regeneration.RegenerateWithDatapath,
		ParentContext:     f.ctx,
	})
	require.NoError(t, ep.WaitForFirstRegeneration(f.ctx))
	return ep
}

// regenerate regenerates ep without its datapath and reports whether that
// succeeded.
func (f *regenFixture) regenerate(ep *endpoint.Endpoint) bool {
	ctx, cancel := context.WithTimeout(f.ctx, 3*time.Second)
	defer cancel()
	return <-ep.RegenerateIfAlive(&regeneration.ExternalRegenerationMetadata{
		Reason:            "test",
		RegenerationLevel: regeneration.RegenerateWithoutDatapath,
		ParentContext:     ctx,
	})
}

func (f *regenFixture) requirePolicyCurrent(t *testing.T) {
	ctx, cancel := context.WithTimeout(f.ctx, 5*time.Second)
	defer cancel()
	err := waitSettled(ctx, 200*time.Millisecond, f.checkPolicyCurrent)
	require.NoError(t, err, "endpoints not on the current selector policy")
}

// checkPolicyCurrent checks that every endpoint is ready and has realized the
// selector policy committed for its identity, and that it is attached.
func (f *regenFixture) checkPolicyCurrent() error {
	var errs error
	for _, ep := range f.epm.GetEndpoints() {
		if state := ep.GetState(); state != endpoint.StateReady {
			errs = errors.Join(errs, fmt.Errorf("endpoint %d: state %s", ep.ID, state))
			continue
		}
		id, err := ep.GetSecurityIdentity()
		if err != nil || id == nil {
			errs = errors.Join(errs, fmt.Errorf("endpoint %d: no identity", ep.ID))
			continue
		}
		res, _, _, found := f.computer.GetIdentityPolicyByIdentity(id)
		if !found || res.NewPolicy == nil {
			errs = errors.Join(errs, fmt.Errorf("endpoint %d: no selector policy committed for identity %d", ep.ID, id.ID))
			continue
		}
		ePolicy := ep.GetDesiredPolicy()
		if ePolicy == nil || ePolicy.SelectorPolicy == nil {
			errs = errors.Join(errs, fmt.Errorf("endpoint %d: no selector policy", ep.ID))
			continue
		}
		detached, _ := ePolicy.SelectorPolicy.IsDetached()
		if ePolicy.SelectorPolicy != res.NewPolicy || detached {
			errs = errors.Join(errs, fmt.Errorf("endpoint %d: identity %d on selector policy rev %d (detached %t), committed rev %d",
				ep.ID, id.ID, ePolicy.SelectorPolicy.GetRevision(), detached, res.NewPolicy.GetRevision()))
		}
	}
	return errs
}
