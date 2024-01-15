// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blang/semver/v4"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/api/v1/observer"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"

	"github.com/cilium/cilium-cli/connectivity/perf/common"
	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/junit"
	"github.com/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium-cli/utils/features"
)

// ConnectivityTest is the root context of the connectivity test suite
// and holds all resources belonging to it. It implements interface
// ConnectivityTest and is instantiated once at the start of the program,
type ConnectivityTest struct {
	// Client connected to a Kubernetes cluster.
	client       *k8s.Client
	hubbleClient observer.ObserverClient

	// CiliumVersion is the detected or assumed version of the Cilium agent
	CiliumVersion semver.Version

	// Features contains the features enabled on the running Cilium cluster
	Features features.Set

	// Parameters to the test suite, specified by the CLI user.
	params Parameters

	// version is the version string of the cilium-cli itself
	version string

	// Clients for source and destination clusters.
	clients *deploymentClients

	ciliumPods        map[string]Pod
	echoPods          map[string]Pod
	echoExternalPods  map[string]Pod
	clientPods        map[string]Pod
	clientCPPods      map[string]Pod
	perfClientPods    []Pod
	perfServerPod     []Pod
	PerfResults       []common.PerfSummary
	echoServices      map[string]Service
	ingressService    map[string]Service
	k8sService        Service
	externalWorkloads map[string]ExternalWorkload

	hostNetNSPodsByNode      map[string]Pod
	secondaryNetworkNodeIPv4 map[string]string // node name => secondary ip
	secondaryNetworkNodeIPv6 map[string]string // node name => secondary ip

	tests     []*Test
	testNames map[string]struct{}

	lastFlowTimestamps map[string]time.Time

	nodes              map[string]*corev1.Node
	controlPlaneNodes  map[string]*corev1.Node
	nodesWithoutCilium map[string]struct{}
	ciliumNodes        map[NodeIdentity]*ciliumv2.CiliumNode

	manifests      map[string]string
	helmYAMLValues string
}

// NodeIdentity uniquely identifies a Node by Cluster and Name.
type NodeIdentity struct{ Cluster, Name string }

func netIPToCIDRs(netIPs []netip.Addr) (netCIDRs []netip.Prefix) {
	for _, ip := range netIPs {
		found := false
		for _, cidr := range netCIDRs {
			if cidr.Addr().Is4() == ip.Is4() && cidr.Contains(ip) {
				found = true
				break
			}
		}
		if found {
			continue
		}

		// Generate a /24 or /64 accordingly
		bits := 24
		if ip.Is6() {
			bits = 64
		}
		netCIDRs = append(netCIDRs, netip.PrefixFrom(ip, bits).Masked())
	}
	return
}

// verbose returns the value of the user-provided verbosity flag.
func (ct *ConnectivityTest) verbose() bool {
	return ct.params.Verbose
}

// verbose returns the value of the user-provided debug flag.
func (ct *ConnectivityTest) debug() bool {
	return ct.params.Debug
}

// timestamp returns the value of the user-provided timestamp flag.
func (ct *ConnectivityTest) timestamp() bool {
	return ct.params.Timestamp
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

// NewConnectivityTest returns a new ConnectivityTest.
func NewConnectivityTest(client *k8s.Client, p Parameters, version string) (*ConnectivityTest, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}

	k := &ConnectivityTest{
		client:                   client,
		params:                   p,
		version:                  version,
		ciliumPods:               make(map[string]Pod),
		echoPods:                 make(map[string]Pod),
		echoExternalPods:         make(map[string]Pod),
		clientPods:               make(map[string]Pod),
		clientCPPods:             make(map[string]Pod),
		perfClientPods:           []Pod{},
		perfServerPod:            []Pod{},
		PerfResults:              []common.PerfSummary{},
		echoServices:             make(map[string]Service),
		ingressService:           make(map[string]Service),
		externalWorkloads:        make(map[string]ExternalWorkload),
		hostNetNSPodsByNode:      make(map[string]Pod),
		secondaryNetworkNodeIPv4: make(map[string]string),
		secondaryNetworkNodeIPv6: make(map[string]string),
		nodes:                    make(map[string]*corev1.Node),
		nodesWithoutCilium:       make(map[string]struct{}),
		ciliumNodes:              make(map[NodeIdentity]*ciliumv2.CiliumNode),
		tests:                    []*Test{},
		testNames:                make(map[string]struct{}),
		lastFlowTimestamps:       make(map[string]time.Time),
		Features:                 features.Set{},
	}

	return k, nil
}

// NewTest creates a new test scope within the ConnectivityTest and returns
// a new Test. This object can be used to set up the environment to execute
// different Scenarios within.
func (ct *ConnectivityTest) NewTest(name string) *Test {
	var member struct{}

	if name == "" {
		panic("empty test name")
	}

	if _, ok := ct.testNames[name]; ok {
		ct.Fatalf("test %s exists in suite", name)
	}

	t := &Test{
		ctx:       ct,
		name:      name,
		scenarios: make(map[Scenario][]*Action),
		cnps:      make(map[string]*ciliumv2.CiliumNetworkPolicy),
		knps:      make(map[string]*networkingv1.NetworkPolicy),
		cegps:     make(map[string]*ciliumv2.CiliumEgressGatewayPolicy),
		verbose:   ct.verbose(),
		logBuf:    &bytes.Buffer{}, // maintain internal buffer by default
		warnBuf:   &bytes.Buffer{},
	}

	// Setting the internal buffer to nil causes the logger to
	// write directly to stdout in verbose or debug mode.
	if ct.verbose() || ct.debug() {
		t.logBuf = nil
	}

	ct.tests = append(ct.tests, t)
	ct.testNames[name] = member

	return t
}

// GetTest returns the test scope for test named "name" if found,
// a non-nil error otherwise.
func (ct *ConnectivityTest) GetTest(name string) (*Test, error) {
	if _, ok := ct.testNames[name]; !ok {
		return nil, fmt.Errorf("test %s not found", name)
	}

	for _, t := range ct.tests {
		if t.name == name {
			return t, nil
		}
	}

	panic("missing test descriptor for a registered name")
}

// MustGetTest returns the test scope for test named "name" if found,
// or panics otherwise.
func (ct *ConnectivityTest) MustGetTest(name string) *Test {
	test, err := ct.GetTest(name)
	if err != nil {
		panic(err)
	}
	return test
}

// SetupAndValidate sets up and validates the connectivity test infrastructure
// such as the client pods and validates the deployment of them along with
// Cilium. This must be run before Run() is called.
func (ct *ConnectivityTest) SetupAndValidate(ctx context.Context, setupAndValidateExtras func(ctx context.Context, ct *ConnectivityTest) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ct.initClients(ctx); err != nil {
		return err
	}
	if err := ct.initCiliumPods(ctx); err != nil {
		return err
	}
	if err := ct.getNodes(ctx); err != nil {
		return err
	}
	if err := ct.getCiliumNodes(ctx); err != nil {
		return err
	}
	// Detect Cilium version after Cilium pods have been initialized and before feature
	// detection.
	if err := ct.detectCiliumVersion(ctx); err != nil {
		return err
	}
	if err := ct.detectFeatures(ctx); err != nil {
		return err
	}
	// Setup and validate all the extras coming from extended functionalities.
	if err := setupAndValidateExtras(ctx, ct); err != nil {
		return err
	}

	if ct.debug() {
		fs := make([]features.Feature, 0, len(ct.Features))
		for f := range ct.Features {
			fs = append(fs, f)
		}
		slices.Sort(fs)
		ct.Debug("Detected features:")
		for _, f := range fs {
			ct.Debugf("  %s: %s", f, ct.Features[f])
		}
	}

	if ct.FlowAggregation() {
		ct.Info("Monitor aggregation detected, will skip some flow validation steps")
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
	if match, _ := ct.Features.MatchRequirements(features.RequireEnabled(features.NodeWithoutCilium)); match {
		if err := ct.detectPodCIDRs(ctx); err != nil {
			return fmt.Errorf("unable to detect pod CIDRs: %w", err)
		}

		if err := ct.detectNodesWithoutCiliumIPs(); err != nil {
			return fmt.Errorf("unable to detect nodes w/o Cilium IPs: %w", err)
		}
	}
	if match, _ := ct.Features.MatchRequirements((features.RequireEnabled(features.CIDRMatchNodes))); match {
		if err := ct.detectNodeCIDRs(ctx); err != nil {
			return fmt.Errorf("unable to detect node CIDRs: %w", err)
		}
	}
	if ct.params.K8sLocalHostTest {
		if err := ct.detectK8sCIDR(ctx); err != nil {
			return fmt.Errorf("unable to detect K8s CIDR: %w", err)
		}
	}
	return nil
}

// Run kicks off execution of all Tests registered to the ConnectivityTest.
// Each Test's Run() method is called within its own goroutine.
func (ct *ConnectivityTest) Run(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	if len(ct.params.DeleteCiliumOnNodes) > 0 {
		// Delete Cilium pods so only the datapath plumbing remains
		ct.Debug("Deleting Cilium pods from specified nodes")
		if err := ct.deleteCiliumPods(ctx); err != nil {
			return err
		}
	}

	ct.Debug("Registered connectivity tests:")
	for _, t := range ct.tests {
		ct.Debugf("  %s", t)
	}

	// Newline denoting start of test output.
	ct.Logf("🏃 Running %d tests ...", len(ct.tests))

	// Execute all tests in the order they were registered by the test suite.
	for i, t := range ct.tests {
		if err := ctx.Err(); err != nil {
			return err
		}

		done := make(chan bool)

		go func() {
			defer func() { done <- true }()

			if err := t.Run(ctx, i+1); err != nil {
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

	if err := ct.writeJunit(); err != nil {
		ct.Failf("writing to junit file %s failed: %s", ct.Params().JunitFile, err)
	}

	if ct.Params().FlushCT {
		var wg sync.WaitGroup

		wg.Add(len(ct.CiliumPods()))
		for _, ciliumPod := range ct.CiliumPods() {
			cmd := strings.Split("cilium bpf ct flush global", " ")
			go func(ctx context.Context, pod Pod) {
				defer wg.Done()

				ct.Debugf("Flushing CT entries in %s/%s", pod.Pod.Namespace, pod.Pod.Name)
				_, err := pod.K8sClient.ExecInPod(ctx, pod.Pod.Namespace, pod.Pod.Name, defaults.AgentContainerName, cmd)
				if err != nil {
					ct.Fatal("failed to flush ct entries: %w", err)
				}
			}(ctx, ciliumPod)
		}

		wg.Wait()
	}

	// Delete conn disrupt pods after running tests. Otherwise, after calling
	// --flush-ct they might get into crashloop state from which it takes time
	// to recover, which makes subsequent tests to fail.
	if ct.Params().IncludeConnDisruptTest && !ct.Params().ConnDisruptTestSetup {
		for _, client := range ct.Clients() {
			if err := ct.DeleteConnDisruptTestDeployment(ctx, client); err != nil {
				return err
			}
		}
	}

	// Report the test results.
	return ct.report()
}

// skip marks the Test as skipped.
func (ct *ConnectivityTest) skip(t *Test, index int, reason string) {
	ct.Logf("[=] Skipping Test [%s] [%d/%d] (%s)", t.Name(), index, len(t.ctx.tests), reason)
	t.skipped = true
}

func (ct *ConnectivityTest) writeJunit() error {
	if ct.Params().JunitFile == "" {
		return nil
	}

	properties := []junit.Property{
		{Name: "Args", Value: strings.Join(os.Args[3:], "|")},
	}
	for key, val := range ct.Params().JunitProperties {
		properties = append(properties, junit.Property{Name: key, Value: val})
	}

	suite := &junit.TestSuite{
		Name:    "connectivity test",
		Package: "cilium",
		Tests:   len(ct.tests),
		Properties: &junit.Properties{
			Properties: properties,
		},
	}

	for i, t := range ct.tests {
		test := &junit.TestCase{
			Name:      t.Name(),
			Classname: "connectivity test",
			Status:    "passed",
			Time:      t.completionTime.Sub(t.startTime).Seconds(),
		}

		// Timestamp of the TestSuite is the first test's start time
		if i == 0 {
			suite.Timestamp = t.startTime.Format("2006-01-02T15:04:05")
		}
		suite.Time += test.Time

		if t.skipped {
			test.Status = "skipped"
			test.Skipped = &junit.Skipped{Message: t.Name() + " skipped"}
			suite.Skipped++
			test.Time = 0
		} else if t.failed {
			test.Status = "failed"
			test.Failure = &junit.Failure{Message: t.Name() + " failed", Type: "failure"}
			suite.Failures++
			msgs := []string{}
			for _, a := range t.failedActions() {
				msgs = append(msgs, a.String())
			}
			test.Failure.Value = strings.Join(msgs, "\n")
		}

		suite.TestCases = append(suite.TestCases, test)
	}

	suites := junit.TestSuites{
		Tests:      suite.Tests,
		Disabled:   suite.Skipped,
		Failures:   suite.Failures,
		Time:       suite.Time,
		TestSuites: []*junit.TestSuite{suite},
	}

	f, err := os.Create(ct.Params().JunitFile)
	if err != nil {
		return err
	}

	if err := suites.WriteReport(f); err != nil {
		if e := f.Close(); e != nil {
			return errors.Join(err, e)
		}
		return err
	}

	return f.Close()
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

	if nf > 0 {
		ct.Header("📋 Test Report")

		// There are failed tests, fetch all failed actions.
		fa := len(ct.failedActions())

		ct.Failf("%d/%d tests failed (%d/%d actions), %d tests skipped, %d scenarios skipped:", nf, nt-nst, fa, na, nst, nss)

		// List all failed actions by test.
		for _, t := range failed {
			ct.Logf("Test [%s]:", t.Name())
			for _, a := range t.failedActions() {
				ct.Log("  ❌", a)
			}
		}

		return fmt.Errorf("%d tests failed", nf)
	}

	if ct.params.Perf {
		ct.Header("🔥 Network Performance Test Summary:")
		ct.Logf("%s", strings.Repeat("-", 200))
		ct.Logf("📋 %-15s | %-10s | %-15s | %-15s | %-15s | %-15s | %-15s | %-15s | %-15s | %-15s | %-15s", "Scenario", "Node", "Test", "Duration", "Min", "Mean", "Max", "P50", "P90", "P99", "Transaction rate OP/s")
		ct.Logf("%s", strings.Repeat("-", 200))
		nodeString := func(sameNode bool) string {
			if sameNode {
				return "same-node"
			}
			return "other-node"
		}
		for _, result := range ct.PerfResults {
			if result.Result.Latency != nil && result.Result.TransactionRateMetric != nil {
				ct.Logf("📋 %-15s | %-10s | %-15s | %-15s | %-15s | %-15s | %-15s | %-15s | %-15s | %-15s | %-12.2f",
					result.PerfTest.Scenario,
					nodeString(result.PerfTest.SameNode),
					result.PerfTest.Test,
					result.PerfTest.Duration,
					result.Result.Latency.Min,
					result.Result.Latency.Avg,
					result.Result.Latency.Max,
					result.Result.Latency.Perc50,
					result.Result.Latency.Perc90,
					result.Result.Latency.Perc99,
					result.Result.TransactionRateMetric.TransactionRate,
				)
			}
		}
		ct.Logf("%s", strings.Repeat("-", 200))
		ct.Logf("%s", strings.Repeat("-", 85))
		ct.Logf("📋 %-15s | %-10s | %-15s | %-15s | %-15s ", "Scenario", "Node", "Test", "Duration", "Throughput Mb/s")
		ct.Logf("%s", strings.Repeat("-", 85))
		for _, result := range ct.PerfResults {
			if result.Result.ThroughputMetric != nil {
				ct.Logf("📋 %-15s | %-10s | %-15s | %-15s | %-12.2f ",
					result.PerfTest.Scenario,
					nodeString(result.PerfTest.SameNode),
					result.PerfTest.Test,
					result.PerfTest.Duration,
					result.Result.ThroughputMetric.Throughput/1000000,
				)
			}
		}
		ct.Logf("%s", strings.Repeat("-", 85))
		if ct.Params().PerfReportDir != "" {
			common.ExportPerfSummaries(ct.PerfResults, ct.Params().PerfReportDir)
		}
	}

	ct.Headerf("✅ All %d tests (%d actions) successful, %d tests skipped, %d scenarios skipped.", nt-nst, na, nst, nss)

	return nil
}

func (ct *ConnectivityTest) enableHubbleClient(ctx context.Context) error {
	ct.Log("🔭 Enabling Hubble telescope...")

	dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	c, err := grpc.DialContext(dialCtx, ct.params.HubbleServer, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}

	ct.hubbleClient = observer.NewObserverClient(c)

	status, err := ct.hubbleClient.ServerStatus(ctx, &observer.ServerStatusRequest{})
	if err != nil {
		ct.Warn("Unable to contact Hubble Relay, disabling Hubble telescope and flow validation:", err)
		ct.Info(`Expose Relay locally with:
   cilium hubble enable
   cilium hubble port-forward&`)
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

func (ct *ConnectivityTest) detectPodCIDRs(ctx context.Context) error {
	for _, client := range ct.Clients() {
		nodes, err := client.ListNodes(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("failed to list nodes: %w", err)
		}

		for _, n := range nodes.Items {
			if _, ok := ct.nodesWithoutCilium[n.Name]; ok {
				// Skip the nodes where Cilium is not installed.
				continue
			}

			pod, ok := ct.hostNetNSPodsByNode[n.Name]
			if !ok {
				// No host-netns pod seems to be running on this node. Skipping
				ct.Warnf("Could not find any host-netns pod running on %s", n.Name)
				continue
			}

			for _, cidr := range n.Spec.PodCIDRs {
				// PodIPs match HostIPs given that the pod is running in host network.
				for _, ip := range pod.Pod.Status.PodIPs {
					f := features.GetIPFamily(ip.IP)
					if strings.Contains(cidr, ":") != (f == features.IPFamilyV6) {
						// Skip if the host IP of the pod mismatches with pod CIDR.
						// Cannot create a route with the gateway IP family
						// mismatching the subnet.
						continue
					}
					ct.params.PodCIDRs = append(ct.params.PodCIDRs, podCIDRs{cidr, ip.IP})
				}
			}
		}
	}

	return nil
}

// detectNodeCIDRs produces one or more CIDRs that cover all nodes in the cluster.
// ipv4 addresses are collapsed in to one or more /24s, and v6 to one or more /64s
func (ct *ConnectivityTest) detectNodeCIDRs(ctx context.Context) error {
	if len(ct.params.NodeCIDRs) > 0 {
		return nil
	}

	nodes, err := ct.client.ListNodes(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list nodes: %w", err)
	}

	nodeIPs := make([]netip.Addr, 0, len(nodes.Items))
	cPIPs := make([]netip.Addr, 0, 1)

	for i, node := range nodes.Items {
		for _, addr := range node.Status.Addresses {
			if addr.Type != "InternalIP" {
				continue
			}

			ip, err := netip.ParseAddr(addr.Address)
			if err != nil {
				continue
			}
			nodeIPs = append(nodeIPs, ip)
			if isControlPlane(&nodes.Items[i]) {
				cPIPs = append(cPIPs, ip)
			}
		}
	}

	if len(nodeIPs) == 0 {
		return fmt.Errorf("detectNodeCIDRs failed: no node IPs disovered")
	}

	// collapse set of IPs in to CIDRs
	nodeCIDRs := netIPToCIDRs(nodeIPs)
	cPCIDRs := netIPToCIDRs(cPIPs)

	ct.params.NodeCIDRs = make([]string, 0, len(nodeCIDRs))
	for _, cidr := range nodeCIDRs {
		ct.params.NodeCIDRs = append(ct.params.NodeCIDRs, cidr.String())
	}
	ct.params.ControlPlaneCIDRs = make([]string, 0, len(cPCIDRs))
	for _, cidr := range cPCIDRs {
		ct.params.ControlPlaneCIDRs = append(ct.params.ControlPlaneCIDRs, cidr.String())
	}
	ct.Debugf("Detected NodeCIDRs: %v", ct.params.NodeCIDRs)
	return nil
}

// detectK8sCIDR produces one CIDR that covers the kube-apiserver address.
// ipv4 addresses are collapsed in to one or more /24s, and v6 to one or more /64s
func (ct *ConnectivityTest) detectK8sCIDR(ctx context.Context) error {
	service, err := ct.client.GetService(ctx, "default", "kubernetes", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get \"kubernetes.default\" service: %w", err)
	}
	addr, err := netip.ParseAddr(service.Spec.ClusterIP)
	if err != nil {
		return fmt.Errorf("failed to parse \"kubernetes.default\" service Cluster IP: %w", err)
	}

	// Generate a /24 or /64 accordingly
	bits := 24
	if addr.Is6() {
		bits = 64
	}
	ct.params.K8sCIDR = netip.PrefixFrom(addr, bits).Masked().String()
	ct.k8sService = Service{Service: service, URLPath: "/healthz"}
	ct.Debugf("Detected K8sCIDR: %q", ct.params.K8sCIDR)
	return nil
}

func (ct *ConnectivityTest) detectNodesWithoutCiliumIPs() error {
	for n := range ct.nodesWithoutCilium {
		pod := ct.hostNetNSPodsByNode[n]
		for _, ip := range pod.Pod.Status.PodIPs {
			hostIP, err := netip.ParseAddr(ip.IP)
			if err != nil {
				return fmt.Errorf("unable to parse nodes without Cilium IP addr %q: %w", ip.IP, err)
			}
			ct.params.NodesWithoutCiliumIPs = append(ct.params.NodesWithoutCiliumIPs,
				nodesWithoutCiliumIP{ip.IP, hostIP.BitLen()})
		}
	}

	return nil
}

func (ct *ConnectivityTest) modifyStaticRoutesForNodesWithoutCilium(ctx context.Context, verb string) error {
	for _, e := range ct.params.PodCIDRs {
		for withoutCilium := range ct.nodesWithoutCilium {
			pod := ct.hostNetNSPodsByNode[withoutCilium]
			_, err := ct.client.ExecInPod(ctx, pod.Pod.Namespace, pod.Pod.Name, hostNetNSDeploymentNameNonCilium,
				[]string{"ip", "route", verb, e.CIDR, "via", e.HostIP},
			)
			ct.Debugf("Modifying (%s) static route on nodes without Cilium (%v): %v",
				verb, withoutCilium,
				[]string{"ip", "route", verb, e.CIDR, "via", e.HostIP},
			)
			if err != nil {
				return fmt.Errorf("failed to %s static route: %w", verb, err)
			}
		}
	}

	return nil
}

// initClients checks if Cilium is installed on the cluster, whether the cluster
// has multiple nodes, and whether or not monitor aggregation is enabled.
// TODO(timo): Split this up, it does a lot.
func (ct *ConnectivityTest) initClients(ctx context.Context) error {
	c := &deploymentClients{
		src: ct.client,
		dst: ct.client,
	}

	if ct.params.MultiCluster != "" && ct.params.SingleNode {
		return fmt.Errorf("single-node test can not be enabled with multi-cluster test")
	}

	// In single-cluster environment, automatically detect a single-node
	// environment so we can skip deploying tests which depend on multiple
	// nodes.
	if ct.params.MultiCluster == "" && !ct.params.SingleNode {
		daemonSet, err := ct.client.GetDaemonSet(ctx, ct.params.CiliumNamespace, ct.params.AgentDaemonSetName, metav1.GetOptions{})
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
		dst, err := k8s.NewClient(ct.params.MultiCluster, "", ct.params.CiliumNamespace)
		if err != nil {
			return fmt.Errorf("unable to create Kubernetes client for remote cluster %q: %w", ct.params.MultiCluster, err)
		}

		c.dst = dst

	}

	ct.clients = c

	return nil
}

// initCiliumPods fetches the Cilium agent pod information from all clients
func (ct *ConnectivityTest) initCiliumPods(ctx context.Context) error {
	for _, client := range ct.clients.clients() {
		ciliumPods, err := client.ListPods(ctx, ct.params.CiliumNamespace, metav1.ListOptions{LabelSelector: ct.params.AgentPodSelector})
		if err != nil {
			return fmt.Errorf("unable to list Cilium pods: %w", err)
		}
		for _, ciliumPod := range ciliumPods.Items {
			// TODO: Can Cilium pod names collide across clusters?
			ct.ciliumPods[ciliumPod.Name] = Pod{
				K8sClient: client,
				Pod:       ciliumPod.DeepCopy(),
			}
		}
	}

	return nil
}

func (ct *ConnectivityTest) getNodes(ctx context.Context) error {
	ct.nodes = make(map[string]*corev1.Node)
	ct.controlPlaneNodes = make(map[string]*corev1.Node)
	ct.nodesWithoutCilium = make(map[string]struct{})
	nodeList, err := ct.client.ListNodes(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("unable to list K8s Nodes: %w", err)
	}

	for _, node := range nodeList.Items {
		node := node
		if canNodeRunCilium(&node) {
			if isControlPlane(&node) {
				ct.controlPlaneNodes[node.ObjectMeta.Name] = node.DeepCopy()
			}
			ct.nodes[node.ObjectMeta.Name] = node.DeepCopy()
		} else {
			ct.nodesWithoutCilium[node.ObjectMeta.Name] = struct{}{}
		}
	}

	return nil
}

func (ct *ConnectivityTest) getCiliumNodes(ctx context.Context) error {
	for _, client := range ct.Clients() {
		nodeList, err := client.ListCiliumNodes(ctx)
		if err != nil {
			return fmt.Errorf("unable to list CiliumNodes: %w", err)
		}

		for _, node := range nodeList.Items {
			ct.ciliumNodes[NodeIdentity{client.ClusterName(), node.ObjectMeta.Name}] = node.DeepCopy()
		}
	}

	return nil
}

// DetectMinimumCiliumVersion returns the smallest Cilium version running in
// the cluster(s)
func (ct *ConnectivityTest) DetectMinimumCiliumVersion(ctx context.Context) (*semver.Version, error) {
	var minVersion *semver.Version
	for name, ciliumPod := range ct.ciliumPods {
		podVersion, err := ciliumPod.K8sClient.GetCiliumVersion(ctx, ciliumPod.Pod)
		if err != nil {
			return nil, fmt.Errorf("unable to parse cilium version on pod %q: %w", name, err)
		}
		if minVersion == nil || podVersion.LT(*minVersion) {
			minVersion = podVersion
		}
	}

	return minVersion, nil
}

// UninstallResources deletes all k8s resources created by the connectivity tests.
func (ct *ConnectivityTest) UninstallResources(ctx context.Context, wait bool) {
	ct.Logf("🔥 Deleting pods in %s namespace...", ct.params.TestNamespace)
	ct.client.DeletePodCollection(ctx, ct.params.TestNamespace, metav1.DeleteOptions{}, metav1.ListOptions{})

	ct.Logf("🔥 Deleting %s namespace...", ct.params.TestNamespace)
	ct.client.DeleteNamespace(ctx, ct.params.TestNamespace, metav1.DeleteOptions{})

	// To avoid cases where test pods are stuck in terminating state because
	// cni (cilium) pods were deleted sooner, wait until test pods are deleted
	// before moving onto deleting cilium pods.
	if wait {
		ct.Logf("⌛ Waiting for %s namespace to be terminated...", ct.params.TestNamespace)
		for {
			// Wait for the test namespace to be terminated. Subsequent connectivity checks would fail
			// if the test namespace is in Terminating state.
			_, err := ct.client.GetNamespace(ctx, ct.params.TestNamespace, metav1.GetOptions{})
			if err == nil {
				time.Sleep(defaults.WaitRetryInterval)
			} else {
				break
			}
		}
	}
}

func (ct *ConnectivityTest) CurlCommand(peer TestPeer, ipFam features.IPFamily, opts ...string) []string {
	cmd := []string{
		"curl",
		"-w", "%{local_ip}:%{local_port} -> %{remote_ip}:%{remote_port} = %{response_code}",
		"--silent", "--fail", "--show-error",
		"--output", "/dev/null",
	}

	if connectTimeout := ct.params.ConnectTimeout.Seconds(); connectTimeout > 0.0 {
		cmd = append(cmd, "--connect-timeout", strconv.FormatFloat(connectTimeout, 'f', -1, 64))
	}
	if requestTimeout := ct.params.RequestTimeout.Seconds(); requestTimeout > 0.0 {
		cmd = append(cmd, "--max-time", strconv.FormatFloat(requestTimeout, 'f', -1, 64))
	}
	if ct.params.CurlInsecure {
		cmd = append(cmd, "--insecure")
	}

	cmd = append(cmd, opts...)
	cmd = append(cmd, fmt.Sprintf("%s://%s%s",
		peer.Scheme(),
		net.JoinHostPort(peer.Address(ipFam), fmt.Sprint(peer.Port())),
		peer.Path()))
	return cmd
}

func (ct *ConnectivityTest) CurlCommandWithOutput(peer TestPeer, ipFam features.IPFamily, opts ...string) []string {
	cmd := []string{"curl", "--silent", "--fail", "--show-error"}

	if connectTimeout := ct.params.ConnectTimeout.Seconds(); connectTimeout > 0.0 {
		cmd = append(cmd, "--connect-timeout", strconv.FormatFloat(connectTimeout, 'f', -1, 64))
	}
	if requestTimeout := ct.params.RequestTimeout.Seconds(); requestTimeout > 0.0 {
		cmd = append(cmd, "--max-time", strconv.FormatFloat(requestTimeout, 'f', -1, 64))
	}

	cmd = append(cmd, opts...)
	cmd = append(cmd, fmt.Sprintf("%s://%s%s",
		peer.Scheme(),
		net.JoinHostPort(peer.Address(ipFam), fmt.Sprint(peer.Port())),
		peer.Path()))
	return cmd
}

func (ct *ConnectivityTest) CurlCommandParallelWithOutput(peer TestPeer, ipFam features.IPFamily, parallel int, opts ...string) []string {
	cmd := []string{
		"curl", "--silent", "--fail", "--show-error",
		"--parallel", "--parallel-immediate", "--parallel-max", fmt.Sprint(parallel),
	}

	if connectTimeout := ct.params.ConnectTimeout.Seconds(); connectTimeout > 0.0 {
		cmd = append(cmd, "--connect-timeout", strconv.FormatFloat(connectTimeout, 'f', -1, 64))
	}
	if requestTimeout := ct.params.RequestTimeout.Seconds(); requestTimeout > 0.0 {
		cmd = append(cmd, "--max-time", strconv.FormatFloat(requestTimeout, 'f', -1, 64))
	}

	cmd = append(cmd, opts...)
	url := fmt.Sprintf("%s://%s%s",
		peer.Scheme(),
		net.JoinHostPort(peer.Address(ipFam), fmt.Sprint(peer.Port())),
		peer.Path())

	for i := 0; i < parallel; i++ {
		cmd = append(cmd, url)
	}

	return cmd
}

func (ct *ConnectivityTest) PingCommand(peer TestPeer, ipFam features.IPFamily) []string {
	cmd := []string{"ping", "-c", "1"}

	if ipFam == features.IPFamilyV6 {
		cmd = append(cmd, "-6")
	}

	if connectTimeout := ct.params.ConnectTimeout.Seconds(); connectTimeout > 0.0 {
		cmd = append(cmd, "-W", strconv.FormatFloat(connectTimeout, 'f', -1, 64))
	}
	if requestTimeout := ct.params.RequestTimeout.Seconds(); requestTimeout > 0.0 {
		cmd = append(cmd, "-w", strconv.FormatFloat(requestTimeout, 'f', -1, 64))
	}

	cmd = append(cmd, peer.Address(ipFam))
	return cmd
}

func (ct *ConnectivityTest) DigCommand(peer TestPeer, ipFam features.IPFamily) []string {
	cmd := []string{"dig", "+time=2", "kubernetes"}

	cmd = append(cmd, fmt.Sprintf("@%s", peer.Address(ipFam)))
	return cmd
}

func (ct *ConnectivityTest) RandomClientPod() *Pod {
	for _, p := range ct.clientPods {
		return &p
	}
	return nil
}

func (ct *ConnectivityTest) Params() Parameters {
	return ct.params
}

func (ct *ConnectivityTest) CiliumPods() map[string]Pod {
	return ct.ciliumPods
}

func (ct *ConnectivityTest) Nodes() map[string]*corev1.Node {
	return ct.nodes
}

func (ct *ConnectivityTest) ControlPlaneNodes() map[string]*corev1.Node {
	return ct.controlPlaneNodes
}

func (ct *ConnectivityTest) CiliumNodes() map[NodeIdentity]*ciliumv2.CiliumNode {
	return ct.ciliumNodes
}

func (ct *ConnectivityTest) ClientPods() map[string]Pod {
	return ct.clientPods
}

func (ct *ConnectivityTest) ControlPlaneClientPods() map[string]Pod {
	return ct.clientCPPods
}

func (ct *ConnectivityTest) HostNetNSPodsByNode() map[string]Pod {
	return ct.hostNetNSPodsByNode
}

func (ct *ConnectivityTest) SecondaryNetworkNodeIPv4() map[string]string {
	return ct.secondaryNetworkNodeIPv4
}

func (ct *ConnectivityTest) SecondaryNetworkNodeIPv6() map[string]string {
	return ct.secondaryNetworkNodeIPv6
}

func (ct *ConnectivityTest) PerfServerPod() []Pod {
	return ct.perfServerPod
}

func (ct *ConnectivityTest) PerfClientPods() []Pod {
	return ct.perfClientPods
}

func (ct *ConnectivityTest) EchoPods() map[string]Pod {
	return ct.echoPods
}

func (ct *ConnectivityTest) EchoServices() map[string]Service {
	return ct.echoServices
}

func (ct *ConnectivityTest) ExternalEchoPods() map[string]Pod {
	return ct.echoExternalPods
}

func (ct *ConnectivityTest) IngressService() map[string]Service {
	return ct.ingressService
}

func (ct *ConnectivityTest) K8sService() Service {
	return ct.k8sService
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
	return ct.Features[features.MonitorAggregation].Enabled
}

func (ct *ConnectivityTest) PostTestSleepDuration() time.Duration {
	return ct.params.PostTestSleepDuration
}

func (ct *ConnectivityTest) K8sClient() *k8s.Client {
	return ct.client
}

func (ct *ConnectivityTest) NodesWithoutCilium() []string {
	return maps.Keys(ct.nodesWithoutCilium)
}

func (ct *ConnectivityTest) Feature(f features.Feature) (features.Status, bool) {
	s, ok := ct.Features[f]
	return s, ok
}

func (ct *ConnectivityTest) Clients() []*k8s.Client {
	return ct.clients.clients()
}
