// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"fmt"
	"os"
	"path"
	"testing"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/test/controlplane/suite"
)

func init() {
	suite.AddTestCase("Policies/k8s", testK8SNetworkPolicy)
}

type direction int

const (
	egress = direction(iota)
	ingress
	both
)

type step struct {
	filename         string
	namespace        string
	direction        direction
	expectedDecision api.Decision
}

var steps = []step{
	{
		filename:         "state1.yaml",
		namespace:        "policy1",
		direction:        egress,
		expectedDecision: api.Allowed,
	},
	{
		filename:         "state2.yaml",
		namespace:        "policy2",
		direction:        ingress,
		expectedDecision: api.Allowed,
	},
	{
		filename:         "state3.yaml",
		namespace:        "policy3",
		direction:        egress,
		expectedDecision: api.Denied,
	},
	{
		filename:         "state4.yaml",
		namespace:        "policy4",
		direction:        ingress,
		expectedDecision: api.Denied,
	},
	{
		filename:         "state5.yaml",
		namespace:        "policy5",
		direction:        both,
		expectedDecision: api.Denied,
	},
}

func testK8SNetworkPolicy(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}

	modConfig := func(c *option.DaemonConfig) {
		c.Debug = true
	}

	for _, version := range []string{"1.20", "1.22", "1.24"} {
		abs := func(f string) string { return path.Join(cwd, "policies", "k8s", "v"+version, f) }

		t.Run("v"+version, func(t *testing.T) {
			test := suite.NewControlPlaneTest(t, "policy-control-plane", version)

			// Feed in initial state and start the agent.
			test.UpdateObjectsFromFile(abs("init.yaml")).StartAgent(modConfig)

			// Run through the test steps
			for _, step := range steps {
				test.UpdateObjectsFromFile(abs(step.filename))
				test.Eventually(func() error { return validate(test, step) })
			}

			test.StopAgent()
		})
	}
}

func validate(test *suite.ControlPlaneTest, step step) error {
	sc := &policy.SearchContext{
		From: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, step.namespace, labels.LabelSourceK8s),
		},
		To: labels.LabelArray{
			labels.NewLabel(k8sConst.PodNamespaceLabel, step.namespace, labels.LabelSourceK8s),
		},
	}

	repo := test.GetAgent().GetPolicyRepository()

	repo.Mutex.RLock()
	ingressDecision := test.GetAgent().GetPolicyRepository().AllowsIngressRLocked(sc)
	egressDecision := test.GetAgent().GetPolicyRepository().AllowsEgressRLocked(sc)
	repo.Mutex.RUnlock()

	if (step.direction == egress || step.direction == both) && egressDecision != step.expectedDecision {
		return fmt.Errorf("failed to verify egress %s, expected: %s, actual: %s",
			step.filename, step.expectedDecision, egressDecision)
	}
	if (step.direction == ingress || step.direction == both) && ingressDecision != step.expectedDecision {
		return fmt.Errorf("failed to verify ingress %s, expected: %s, actual: %s",
			step.filename, step.expectedDecision, egressDecision)
	}

	return nil
}
