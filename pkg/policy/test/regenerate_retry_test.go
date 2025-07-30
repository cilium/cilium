// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

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

type failOnceCertManager struct {
	remaining atomic.Int32
}

func (m *failOnceCertManager) GetTLSContext(
	_ context.Context, tlsCtx *api.TLSContext, _ string,
) (ca, public, private string, inlineSecrets bool, err error) {
	if m.remaining.Add(-1) >= 0 {
		return "", "", "", false, errors.New("injected: transient cert fetch failure")
	}
	name := tlsCtx.Secret.Name
	return "fake ca " + name, "fake public " + name, "fake private " + name, true, nil
}

func TestRegenerateRetries(t *testing.T) {
	// trigger.waiter and SelectorCache.handleUserNotifications are known not to
	// shut down on hive.Stop. They live for the test process lifetime in
	// production too.
	t.Cleanup(func() {
		testutils.GoleakVerifyNone(t,
			testutils.GoleakIgnoreAnyFunction("github.com/cilium/cilium/pkg/trigger.(*Trigger).waiter"),
			testutils.GoleakIgnoreAnyFunction("github.com/cilium/cilium/pkg/policy.(*SelectorCache).handleUserNotifications"),
		)
	})

	version.Force(testk8s.DefaultVersion)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)

	log := hivetest.Logger(t)

	certMgr := &failOnceCertManager{}
	certMgr.remaining.Store(1)

	f := newTestFixture(t, log, certMgr)

	podLabels := labels.LabelArray{
		labels.NewLabel("io.kubernetes.pod.namespace", "default", labels.LabelSourceK8s),
		labels.NewLabel("app", "test", labels.LabelSourceK8s),
	}
	podID, _, err := f.allocator.AllocateIdentity(ctx, podLabels.Labels(), true, identity.NumericIdentity(0))
	require.NoError(t, err)

	ep := f.templateEP.CopyFromTemplate()
	require.NoError(t, f.epm.AddEndpoint(ep))
	_ = ep.UpdateLabels(ctx, labels.LabelSourceAny, podID.Labels, nil, true)

	rule := &api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.NewLabel("app", "test", labels.LabelSourceK8s)),
		Egress: []api.EgressRule{{
			ToPorts: []api.PortRule{{
				Ports: []api.PortProtocol{{Port: "443", Protocol: "TCP"}},
				TerminatingTLS: &api.TLSContext{
					Secret: &api.Secret{
						Namespace: "default",
						Name:      "tls-secret",
					},
				},
				Rules: &api.L7Rules{HTTP: []api.PortRuleHTTP{{}}},
			}},
		}},
		Labels: labels.LabelArray{
			labels.NewLabel(k8sConst.PolicyLabelName, "retryRule", labels.LabelSourceAny),
		},
	}
	require.NoError(t, rule.Sanitize())

	done := make(chan uint64, 1)
	f.importer.UpdatePolicy(&policytypes.PolicyUpdate{
		Rules:    policyutils.RulesToPolicyEntries(api.Rules{rule}),
		Source:   source.CustomResource,
		Resource: ipcachetypes.NewResourceID(ipcachetypes.ResourceKindCNP, "default", "retry-test"),
		DoneChan: done,
	})

	var rev uint64
	select {
	case rev = <-done:
	case <-ctx.Done():
		t.Fatal("policy import timed out")
	}

	_ = ep.RegenerateIfAlive(&regeneration.ExternalRegenerationMetadata{
		Reason:                  "transient cert failure test",
		RegenerationLevel:       regeneration.RegenerateWithDatapath,
		ParentContext:           ctx,
		PolicyRevisionToWaitFor: rev,
	})

	waitCtx, waitCancel := context.WithTimeout(ctx, 10*time.Second)
	defer waitCancel()
	select {
	case <-ep.WaitForPolicyRevision(waitCtx, rev, nil):
	case <-waitCtx.Done():
		t.Fatalf("endpoint did not reach policy revision %d", rev)
	}

	require.Negative(t, certMgr.remaining.Load())
}
