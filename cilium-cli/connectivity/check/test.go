// Copyright 2020-2021 Authors of Cilium
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

package check

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
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

// willRun returns false if all of the Test's Scenarios will be skipped.
func (t *Test) willRun() bool {
	var sc int

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
	if t.failed && t.Context().params.PauseOnFail {
		t.Log("Pausing after test failure, press the Enter key to continue:")
		fmt.Scanln()
	}

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

	t.ctx.Log()
	t.ctx.Logf("[=] Test [%s]", t.Name())

	if err := t.setup(ctx); err != nil {
		return fmt.Errorf("setting up test: %w", err)
	}

	for s := range t.scenarios {
		if err := ctx.Err(); err != nil {
			return err
		}

		sn := t.scenarioName(s)

		if !t.Context().params.testEnabled(sn) {
			t.skip(s)
			continue
		}

		t.Logf("[-] Scenario [%s]", sn)

		s.Run(ctx, t)
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
		t.Fatal("Error parsing policy YAML: %w", err)
	}

	if err := t.addCNPs(pl...); err != nil {
		t.Fatal("adding CNPs to policy context: %w", err)
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
