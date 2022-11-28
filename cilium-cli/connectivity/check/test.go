// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/sysdump"
)

const (
	// kubernetesSourcedLabelPrefix is the optional prefix used in labels to
	// indicate they are sourced from Kubernetes.
	// NOTE: For some reason, ':' gets replaced by '.' in keys so we use that instead.
	kubernetesSourcedLabelPrefix = "k8s."

	// anySourceLabelPrefix is the optional prefix used in labels to
	// indicate they could be from anywhere.
	// NOTE: For some reason, ':' gets replaced by '.' in keys so we use that instead.
	anySourceLabelPrefix = "any."
)

type Test struct {
	// Reference to the enclosing test suite for logging etc.
	ctx *ConnectivityTest

	// Name of the test. Must be unique within the scope of a test run.
	name string

	// True if the Test is marked as skipped.
	skipped bool

	// True if the Test is marked as failed.
	failed bool

	// requirements is a list of required Cilium features which need to match
	// for this test to be run
	requirements []FeatureRequirement

	// Scenarios registered to this test.
	scenarios map[Scenario][]*Action

	// Scenarios marked as skipped during execution.
	// Needs to be stored as a list, these are implemented in another package.
	scenariosSkipped []Scenario

	// Policies active during this test.
	cnps map[string]*ciliumv2.CiliumNetworkPolicy

	expectFunc ExpectationsFunc

	// Start time of the test.
	startTime time.Time

	// Buffer to store output until it's flushed by a failure.
	// Unused when run in verbose or debug mode.
	logMu   sync.RWMutex
	logBuf  io.ReadWriter
	warnBuf *bytes.Buffer
	verbose bool

	// List of functions to be called when Run() returns.
	finalizers []func() error
}

func (t *Test) String() string {
	return fmt.Sprintf("<Test %s, %d scenarios, %d CNPs, expectFunc %v>", t.name, len(t.scenarios), len(t.cnps), t.expectFunc)
}

// Name returns the name of the test.
func (t *Test) Name() string {
	return t.name
}

// ScenarioName returns the Test name and Scenario name concatenated in
// a standard way. Scenario names are not unique, as they can occur multiple
// times in the same Test.
func (t *Test) scenarioName(s Scenario) string {
	return fmt.Sprintf("%s/%s", t.Name(), s.Name())
}

// scenarioEnabled returns true if the given scenario is enabled based on the
// set of enabled tests, and if the given scenario also meets the feature
// requirements of the deployed cilium installation
func (t *Test) scenarioEnabled(s Scenario) bool {
	var reqs []FeatureRequirement
	if cs, ok := s.(ConditionalScenario); ok {
		reqs = cs.Requirements()
	}

	return t.Context().params.testEnabled(t.scenarioName(s)) &&
		t.Context().features.MatchRequirements(reqs...)
}

// Context returns the enclosing context of the Test.
func (t *Test) Context() *ConnectivityTest {
	return t.ctx
}

// setup sets up the environment for the Test to execute in, like applying CNPs.
func (t *Test) setup(ctx context.Context) error {

	// Apply CNPs to the cluster.
	if err := t.applyPolicies(ctx); err != nil {
		t.ciliumLogs(ctx)
		return fmt.Errorf("applying network policies: %w", err)
	}

	return nil
}

// skip adds Scenario s to the Test's list of skipped Scenarios.
// This list is kept for reporting purposes.
func (t *Test) skip(s Scenario) {
	t.scenariosSkipped = append(t.scenariosSkipped, s)
	t.Logf("[-] Skipping Scenario [%s]", t.scenarioName(s))
}

// willRun returns false if all of the Test's Scenarios will be skipped, or
// if any of its FeatureRequirements does not match
func (t *Test) willRun() bool {
	var sc int

	if !t.Context().features.MatchRequirements(t.requirements...) {
		return false
	}

	for s := range t.scenarios {
		if !t.Context().params.testEnabled(t.scenarioName(s)) {
			sc++
		}
	}

	return sc != len(t.scenarios)
}

// finalize runs all the Test's registered finalizers.
// Failures encountered executing finalizers will fail the Test.
func (t *Test) finalize() {
	t.Debug("Finalizing Test", t.Name())

	for _, f := range t.finalizers {
		if err := f(); err != nil {
			t.Failf("Error finalizing '%s': %s", t.Name(), err)
		}
	}
}

// Run executes all Scenarios registered to the Test.
func (t *Test) Run(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// Steps to execute when all Scenarios have finished executing,
	// whether they were successful or not. Scenario.Run() might call Fatal(),
	// in which case this function executes as normal.
	defer func() {
		// Run all of the Test's registered finalizers.
		t.finalize()
	}()

	if len(t.scenarios) == 0 {
		t.Fail("Test has no Scenarios")
	}

	// Skip the Test if all of its Scenarios are skipped.
	if !t.willRun() {
		t.Context().skip(t)
		return nil
	}

	// Store start time of the Test.
	t.startTime = time.Now()

	t.ctx.Logf("[=] Test [%s]", t.Name())

	if err := t.setup(ctx); err != nil {
		return fmt.Errorf("setting up test: %w", err)
	}

	if t.logBuf != nil {
		t.ctx.Timestamp()
	}

	for s := range t.scenarios {
		if err := ctx.Err(); err != nil {
			return err
		}

		if !t.scenarioEnabled(s) {
			t.skip(s)
			continue
		}

		t.Logf("[-] Scenario [%s]", t.scenarioName(s))

		s.Run(ctx, t)
	}

	if t.logBuf != nil {
		fmt.Fprintln(t.ctx.params.Writer)
	}

	// Don't add any more code here, as Scenario.Run() can call Fatal() and
	// terminate this goroutine.

	return nil
}

// WithPolicy takes a string containing a YAML policy document and adds
// the polic(y)(ies) to the scope of the Test, to be applied when the test
// starts running.
func (t *Test) WithPolicy(policy string) *Test {
	pl, err := parsePolicyYAML(policy)
	if err != nil {
		t.Fatalf("Parsing policy YAML: %s", err)
	}

	// Change the default test namespace as required.
	for i := range pl {
		pl[i].Namespace = t.ctx.params.TestNamespace
		if pl[i].Spec != nil {
			for _, k := range []string{
				k8sConst.PodNamespaceLabel,
				kubernetesSourcedLabelPrefix + k8sConst.PodNamespaceLabel,
				anySourceLabelPrefix + k8sConst.PodNamespaceLabel,
			} {
				for _, e := range pl[i].Spec.Egress {
					for _, es := range e.ToEndpoints {
						if n, ok := es.MatchLabels[k]; ok && n == defaults.ConnectivityCheckNamespace {
							es.MatchLabels[k] = t.ctx.params.TestNamespace
						}
					}
				}
				for _, e := range pl[i].Spec.Ingress {
					for _, es := range e.FromEndpoints {
						if n, ok := es.MatchLabels[k]; ok && n == defaults.ConnectivityCheckNamespace {
							es.MatchLabels[k] = t.ctx.params.TestNamespace
						}
					}
				}

				for _, e := range pl[i].Spec.EgressDeny {
					for _, es := range e.ToEndpoints {
						if n, ok := es.MatchLabels[k]; ok && n == defaults.ConnectivityCheckNamespace {
							es.MatchLabels[k] = t.ctx.params.TestNamespace
						}
					}
				}

				for _, e := range pl[i].Spec.IngressDeny {
					for _, es := range e.FromEndpoints {
						if n, ok := es.MatchLabels[k]; ok && n == defaults.ConnectivityCheckNamespace {
							es.MatchLabels[k] = t.ctx.params.TestNamespace
						}
					}
				}
			}
		}
	}

	if err := t.addCNPs(pl...); err != nil {
		t.Fatalf("Adding CNPs to policy context: %s", err)
	}
	return t
}

// WithScenarios adds Scenarios to Test in the given order.
func (t *Test) WithScenarios(sl ...Scenario) *Test {
	// Disallow adding the same Scenario object multiple times.
	for _, s := range sl {
		if _, ok := t.scenarios[s]; ok {
			t.Fatalf("Scenario %v already in %s's list of Scenarios", s, t)
		}

		t.scenarios[s] = make([]*Action, 0)
	}

	return t
}

// WithFeatureRequirements adds FeatureRequirements to Test, all of which
// must be satisfied in order for the test to be run
func (t *Test) WithFeatureRequirements(reqs ...FeatureRequirement) *Test {
	t.requirements = append(t.requirements, reqs...)
	return t
}

// NewAction creates a new Action. s must be the Scenario the Action is created
// for, name should be a visually-distinguishable name, src is the execution
// Pod of the action, and dst is the network target the Action will connect to.
func (t *Test) NewAction(s Scenario, name string, src *Pod, dst TestPeer) *Action {
	a := newAction(t, name, s, src, dst)

	// Obtain the expected result for this particular action by calling
	// the registered expectation function.
	a.expEgress, a.expIngress = t.expectations(a)

	// Store a list of Actions per Scenario.
	t.scenarios[s] = append(t.scenarios[s], a)

	return a
}

// failedActions returns a list of failed Actions in the Test.
func (t *Test) failedActions() []*Action {
	var out []*Action

	for _, s := range t.scenarios {
		for _, a := range s {
			if a.failed {
				out = append(out, a)
			}
		}
	}

	return out
}

func (t *Test) NodesWithoutCilium() []string {
	return t.ctx.NodesWithoutCilium()
}

func (t *Test) collectSysdump() {
	collector, err := sysdump.NewCollector(t.ctx.K8sClient(), t.ctx.params.SysdumpOptions, time.Now(), t.ctx.version)
	if err != nil {
		t.Failf("Failed to create sysdump collector: %v", err)
		return
	}

	if err = collector.Run(); err != nil {
		t.Failf("Failed to collect sysdump: %v", err)
	}
}
