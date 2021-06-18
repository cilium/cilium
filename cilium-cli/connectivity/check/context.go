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
	"strings"
	"time"

	"google.golang.org/grpc"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/observer"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/k8s"
)

// ConnectivityTest is the root context of the connectivity test suite
// and holds all resources belonging to it. It implements interface
// ConnectivityTest and is instantiated once at the start of the program,
type ConnectivityTest struct {
	// Client connected to a Kubernetes cluster.
	client       *k8s.Client
	hubbleClient observer.ObserverClient

	flowAggregation bool

	// Parameters to the test suite, specified by the CLI user.
	params Parameters

	// Clients for source and destination clusters.
	clients *deploymentClients

	ciliumPods        map[string]Pod
	echoPods          map[string]Pod
	clientPods        map[string]Pod
	echoServices      map[string]Service
	externalWorkloads map[string]ExternalWorkload

	tests map[string]*Test

	lastFlowTimestamps map[string]time.Time
}

// verbose returns the value of the user-provided verbosity flag.
func (ct *ConnectivityTest) verbose() bool {
	return ct.params.Verbose
}

// verbose returns the value of the user-provided debug flag.
func (ct *ConnectivityTest) debug() bool {
	return ct.params.Debug
}

// actions returns a list of all Actions registered under the test context.
func (ct *ConnectivityTest) actions() []*Action {
	var out []*Action

	for _, t := range ct.tests {
		for _, al := range t.scenarios {
			out = append(out, al...)
		}
	}

	return out
}

// skippedTests returns a list of Tests that were marked as skipped at the
// start of the test suite.
func (ct *ConnectivityTest) skippedTests() []*Test {
	var out []*Test

	for _, t := range ct.tests {
		if t.skipped {
			out = append(out, t)
		}
	}

	return out
}

// skippedScenarios returns a list of Scenarios that were marked as skipped.
func (ct *ConnectivityTest) skippedScenarios() []Scenario {
	var out []Scenario

	for _, t := range ct.tests {
		out = append(out, t.scenariosSkipped...)
	}

	return out
}

// failedTests returns a list of Tests that encountered a failure.
func (ct *ConnectivityTest) failedTests() []*Test {
	var out []*Test

	for _, t := range ct.tests {
		if t.skipped {
			continue
		}
		if t.failed {
			out = append(out, t)
		}
	}

	return out
}

// failedActions returns a list of all failed Actions.
func (ct *ConnectivityTest) failedActions() []*Action {
	var out []*Action

	for _, t := range ct.failedTests() {
		out = append(out, t.failedActions()...)
	}

	return out
}

// warnings returns the total amount of warnings across all Tests.
func (ct *ConnectivityTest) warnings() uint {
	var out uint

	for _, t := range ct.tests {
		out = out + t.warnings
	}

	return out
}

// NewConnectivityTest returns a new ConnectivityTest.
func NewConnectivityTest(client *k8s.Client, p Parameters) (*ConnectivityTest, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}

	k := &ConnectivityTest{
		client:             client,
		params:             p,
		ciliumPods:         make(map[string]Pod),
		echoPods:           make(map[string]Pod),
		clientPods:         make(map[string]Pod),
		echoServices:       make(map[string]Service),
		externalWorkloads:  make(map[string]ExternalWorkload),
		tests:              make(map[string]*Test),
		lastFlowTimestamps: make(map[string]time.Time),
	}

	return k, nil
}

// NewTest creates a new test scope within the ConnectivityTest and returns
// a new Test. This object can be used to set up the environment to execute
// different Scenarios within.
func (ct *ConnectivityTest) NewTest(name string) *Test {
	if name == "" {
		panic("empty test name")
	}

	if _, ok := ct.tests[name]; ok {
		ct.Fatalf("test %s exists in suite", name)
	}

	t := &Test{
		ctx:       ct,
		name:      name,
		scenarios: make(map[Scenario][]*Action),
		cnps:      make(map[string]*ciliumv2.CiliumNetworkPolicy),
		verbose:   ct.verbose(),
		logBuf:    &bytes.Buffer{}, // maintain internal buffer by default
		warnBuf:   &bytes.Buffer{},
	}

	// Setting the internal buffer to nil causes the logger to
	// write directly to stdout in verbose or debug mode.
	if ct.verbose() || ct.debug() {
		t.logBuf = nil
	}

	ct.tests[name] = t

	return t
}

// Run kicks off execution of all Tests registered to the ConnectivityTest.
// Each Test's Run() method is called within its own goroutine.
func (ct *ConnectivityTest) Run(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if err := ct.initClients(ctx); err != nil {
		return err
	}

	if err := ct.deploy(ctx); err != nil {
		return err
	}

	if err := ct.validateDeployment(ctx); err != nil {
		return err
	}

	if ct.params.Hubble {
		if err := ct.enableHubbleClient(ctx); err != nil {
			return fmt.Errorf("unable to create hubble client: %s", err)
		}
	}

	ct.Debug("Registered connectivity tests:")
	for _, t := range ct.tests {
		ct.Debugf("  %s", t)
	}

	// Newline denoting start of test output.
	ct.Log("🏃 Running tests...")

	// Execute all tests in the order they were registered by the test suite.
	for _, t := range ct.tests {
		if err := ctx.Err(); err != nil {
			return err
		}

		done := make(chan bool)

		go func() {
			defer func() { done <- true }()

			if err := t.Run(ctx); err != nil {
				// We know for sure we're inside a separate goroutine, so Fatal()
				// is safe and will properly record failure statistics.
				t.Fatalf("Running test %s: %s", t.Name(), err)
			}

			// Exit immediately if context was cancelled.
			if err := ctx.Err(); err != nil {
				return
			}

			// Pause after each test run if requested by the user.
			if duration := ct.PostTestSleepDuration(); duration != time.Duration(0) {
				ct.Infof("Pausing for %s after test %s", duration, t)
				time.Sleep(duration)
			}
		}()

		// Waiting for the goroutine to finish before starting another Test.
		<-done
	}

	// Report the test results.
	return ct.report()
}

// skip marks the Test as skipped.
func (ct *ConnectivityTest) skip(t *Test) {
	ct.Log()
	ct.Logf("[=] Skipping Test [%s]", t.Name())
	t.skipped = true
}

func (ct *ConnectivityTest) report() error {
	total := ct.tests
	actions := ct.actions()
	skippedTests := ct.skippedTests()
	skippedScenarios := ct.skippedScenarios()
	failed := ct.failedTests()

	nt := len(total)
	na := len(actions)
	nst := len(skippedTests)
	nss := len(skippedScenarios)
	nf := len(failed)
	nw := ct.warnings()

	if nf > 0 {
		ct.Header("📋 Test Report")

		// There are failed tests, fetch all failed actions.
		fa := len(ct.failedActions())

		ct.Failf("%d/%d tests failed (%d/%d actions), %d warnings, %d tests skipped, %d scenarios skipped:", nf, nt-nst, fa, na, nw, nst, nss)

		// List all failed actions by test.
		for _, t := range failed {
			ct.Logf("Test [%s]:", t.Name())
			for _, a := range t.failedActions() {
				ct.Log("  ❌", a)
			}
		}

		return fmt.Errorf("%d tests failed", nf)
	}

	ct.Headerf("✅ All %d tests (%d actions) successful, %d warnings, %d tests skipped, %d scenarios skipped.", nt-nst, na, nw, nst, nss)

	return nil
}

func (ct *ConnectivityTest) enableHubbleClient(ctx context.Context) error {
	ct.Log("🔭 Enabling Hubble telescope...")

	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	c, err := grpc.DialContext(dialCtx, ct.params.HubbleServer, grpc.WithInsecure())
	if err != nil {
		return err
	}

	ct.hubbleClient = observer.NewObserverClient(c)

	status, err := ct.hubbleClient.ServerStatus(ctx, &observer.ServerStatusRequest{})
	if err != nil {
		ct.Warn("Unable to contact Hubble Relay, disabling Hubble telescope and flow validation:", err)
		ct.Info("Expose Relay locally with: kubectl port-forward -n kube-system deployment/hubble-relay 4245:4245")
		ct.hubbleClient = nil
		ct.params.Hubble = false

		if ct.params.FlowValidation == FlowValidationModeStrict {
			ct.Fail("In --flow-validation=strict mode, Hubble must be available to validate flows")
			return fmt.Errorf("hubble is not available: %w", err)
		}
	} else {
		ct.Infof("Hubble is OK, flows: %d/%d", status.NumFlows, status.MaxFlows)
	}

	return nil
}

func (ct *ConnectivityTest) logAggregationMode(ctx context.Context, client *k8s.Client) (string, error) {
	cm, err := client.GetConfigMap(ctx, ct.params.CiliumNamespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}

	if cm.Data == nil {
		return "", fmt.Errorf("ConfigMap %q does not contain any configuration", defaults.ConfigMapName)
	}

	// Monitor aggregation level defaults to none.
	v, ok := cm.Data[defaults.ConfigMapKeyMonitorAggregation]
	if !ok {
		return "none", nil
	}

	// Comparisons will be in lower case.
	return strings.ToLower(v), nil
}

// initClients checks if Cilium is installed on the cluster, whether the cluster
// has multiple nodes, and whether or not monitor aggregation is enabled.
// TODO(timo): Split this up, it does a lot.
func (ct *ConnectivityTest) initClients(ctx context.Context) error {
	c := &deploymentClients{
		src: ct.client,
		dst: ct.client,
	}

	if a, _ := ct.logAggregationMode(ctx, c.src); a != defaults.ConfigMapValueMonitorAggregatonNone {
		ct.flowAggregation = true
	}

	if ct.params.MultiCluster != "" && ct.params.SingleNode {
		return fmt.Errorf("single-node test can not be enabled with multi-cluster test")
	}

	// In single-cluster environment, automatically detect a single-node
	// environment so we can skip deploying tests which depend on multiple
	// nodes.
	if ct.params.MultiCluster == "" && !ct.params.SingleNode {
		daemonSet, err := ct.client.GetDaemonSet(ctx, ct.params.CiliumNamespace, defaults.AgentDaemonSetName, metav1.GetOptions{})
		if err != nil {
			ct.Fatal("Unable to determine status of Cilium DaemonSet. Run \"cilium status\" for more details")
			return fmt.Errorf("unable to determine status of Cilium DaemonSet: %w", err)
		}

		isSingleNode := false
		if daemonSet.Status.DesiredNumberScheduled == 1 {
			isSingleNode = true
		} else {
			nodes, err := ct.client.ListNodes(ctx, metav1.ListOptions{})
			if err != nil {
				ct.Fatal("Unable to list nodes.")
				return fmt.Errorf("unable to list nodes: %w", err)
			}

			numWorkerNodes := len(nodes.Items)
			for _, n := range nodes.Items {
				for _, t := range n.Spec.Taints {
					// cannot schedule connectivity test pods on
					// master node.
					if t.Key == "node-role.kubernetes.io/master" {
						numWorkerNodes--
					}
				}
			}

			isSingleNode = numWorkerNodes == 1
		}

		if isSingleNode {
			ct.Info("Single-node environment detected, enabling single-node connectivity test")
			ct.params.SingleNode = true
		}
	} else if ct.params.MultiCluster != "" {
		dst, err := k8s.NewClient(ct.params.MultiCluster, "")
		if err != nil {
			return fmt.Errorf("unable to create Kubernetes client for remote cluster %q: %w", ct.params.MultiCluster, err)
		}

		c.dst = dst

		if a, _ := ct.logAggregationMode(ctx, c.dst); a != defaults.ConfigMapValueMonitorAggregatonNone {
			ct.flowAggregation = true
		}
	}

	if ct.flowAggregation {
		ct.Info("Monitor aggregation detected, will skip some flow validation steps")
	}

	ct.clients = c

	return nil
}

func (ct *ConnectivityTest) RandomClientPod() *Pod {
	for _, p := range ct.clientPods {
		return &p
	}
	return nil
}

func (ct *ConnectivityTest) CiliumPods() map[string]Pod {
	return ct.ciliumPods
}

func (ct *ConnectivityTest) ClientPods() map[string]Pod {
	return ct.clientPods
}

func (ct *ConnectivityTest) EchoPods() map[string]Pod {
	return ct.echoPods
}

func (ct *ConnectivityTest) EchoServices() map[string]Service {
	return ct.echoServices
}

func (ct *ConnectivityTest) ExternalWorkloads() map[string]ExternalWorkload {
	return ct.externalWorkloads
}

func (ct *ConnectivityTest) HubbleClient() observer.ObserverClient {
	return ct.hubbleClient
}

func (ct *ConnectivityTest) PrintFlows() bool {
	return ct.params.PrintFlows
}

func (ct *ConnectivityTest) AllFlows() bool {
	return ct.params.AllFlows
}

func (ct *ConnectivityTest) FlowAggregation() bool {
	return ct.flowAggregation
}

func (ct *ConnectivityTest) PostTestSleepDuration() time.Duration {
	return ct.params.PostTestSleepDuration
}
