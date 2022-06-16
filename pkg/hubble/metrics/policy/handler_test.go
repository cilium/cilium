// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package policy

import (
	"context"
	"strings"
	"testing"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestPolicyHandler(t *testing.T) {
	registry := prometheus.NewRegistry()
	h := &policyHandler{}
	assert.NoError(t, h.Init(registry, api.Options{}))
	assert.NoError(t, testutil.CollectAndCompare(h.verdicts, strings.NewReader("")))
	flow := flowpb.Flow{
		EventType:        &flowpb.CiliumEventType{Type: monitorAPI.MessageTypePolicyVerdict},
		TrafficDirection: flowpb.TrafficDirection_EGRESS,
		PolicyMatchType:  monitorAPI.PolicyMatchNone,
	}

	h.ProcessFlow(context.Background(), &flow)
	flow.TrafficDirection = flowpb.TrafficDirection_INGRESS
	flow.PolicyMatchType = monitorAPI.PolicyMatchL3L4
	h.ProcessFlow(context.Background(), &flow)
	expected := strings.NewReader(`# HELP hubble_policy_verdicts_total Total number of Cilium network policy verdicts
# TYPE hubble_policy_verdicts_total counter
hubble_policy_verdicts_total{direction="egress",match="none"} 1
hubble_policy_verdicts_total{direction="ingress",match="l3-l4"} 1
`)
	assert.NoError(t, testutil.CollectAndCompare(h.verdicts, expected))
}
