// Copyright 2021 Authors of Cilium
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
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type HTTP struct {
	Status string
	Method string
	URL    string
}

type Result struct {
	// Request is dropped
	Drop bool

	// No flows are to be expected. Used for ingress when egress drops
	None bool

	// DNSProxy is true when DNS Proxy is to be expected, only valid for egress
	DNSProxy bool

	// L7Proxy is true when L7 proxy (e.g., Envoy) is to be expected
	L7Proxy bool

	// HTTPStatus is true when a HTTP status code in response is to be expected
	HTTP HTTP
}

var (
	ResultOK      = Result{}
	ResultDNSOK   = Result{DNSProxy: true}
	ResultNone    = Result{None: true}
	ResultDrop    = Result{Drop: true}
	ResultDNSDrop = Result{Drop: true, DNSProxy: true}
)

func (r Result) String() string {
	if r.None {
		return "None"
	}
	ret := "Allow"
	if r.Drop {
		ret = "Drop"
	}
	if r.DNSProxy {
		ret += "-DNS"
	}
	if r.L7Proxy {
		ret += "-L7"
	}
	if r.HTTP.Status != "" || r.HTTP.Method != "" || r.HTTP.URL != "" {
		ret += "-HTTP"
	}
	if r.HTTP.Method != "" {
		ret += "-"
		ret += r.HTTP.Method
	}
	if r.HTTP.URL != "" {
		ret += "-"
		ret += r.HTTP.URL
	}
	if r.HTTP.Status != "" {
		ret += "-"
		ret += r.HTTP.Status
	}
	return ret
}

type GetExpectations func(t *TestRun) (egress, ingress Result)

type Policy interface {
	// WithPolicy attaches a policy YAML with to a test case
	WithPolicy(yaml string) ConnectivityTest

	// WithExpectations attaches a function that returns test case expected policy enforcement results
	WithExpectations(f GetExpectations) ConnectivityTest

	// getExpectations is for internal use only
	getExpectations(t *TestRun) (egress, ingress Result)
}

// PolicyContext implements ConnectivityTest interface so that
// policies can be applied between tests and policy apply failures can
// be reported like any other test results.
type PolicyContext struct {
	runner     ConnectivityTest
	err        error
	CNPs       []*ciliumv2.CiliumNetworkPolicy
	expectFunc GetExpectations
	policyOnly bool
}

// WithPolicyRunner sets the test runner to use and stores the policy for the tests
func (pc *PolicyContext) WithPolicyRunner(runner ConnectivityTest, yaml string) ConnectivityTest {
	pc.runner = runner
	return pc.WithPolicy(yaml)
}

// PolicyOnly returns true if there is no traffic scenario with this PolicyContext
func (pc *PolicyContext) PolicyOnly() bool {
	return pc.policyOnly
}

// Name returns the absolute name of the policy
func (pc *PolicyContext) Name() string {
	if pc.runner != nil {
		return pc.runner.Name()
	}
	if len(pc.CNPs) == 0 {
		return fmt.Sprintf("PolicyContext %p", pc)
	}
	return fmt.Sprintf("%s/%s", pc.CNPs[0].Namespace, pc.CNPs[0].Name)
}

// Run applies the policy, use no policy to delete all policies
func (pc *PolicyContext) Run(ctx context.Context, c TestContext) {
	if pc.err != nil {
		c.Log("❌ policy parsing failed with error: %s", pc.err)
		c.Report(TestResult{
			Name:     pc.Name(),
			Failures: 1,
			Warnings: 0,
		})
		return
	}
	if pc.runner != nil {
		failures, cleanup := pc.ApplyPolicy(ctx, c)
		c.(*K8sConnectivityCheck).policyFailures = failures
		defer cleanup()

		if failures > 0 {
			c.Log("❌ policy apply failed")
			c.Report(TestResult{
				Name:     pc.Name(),
				Failures: 1,
				Warnings: 0,
			})
			return
		}
		pc.runner.Run(ctx, c)
	} else {
		failures := c.ApplyCNPs(ctx, true, pc.CNPs)
		if failures > 0 {
			c.Log("❌ policy apply failed")
		}
		c.Report(TestResult{
			Name:     pc.Name(),
			Failures: failures,
			Warnings: 0,
		})
	}
}

// WithPolicy sets the policy to use during tests
func (pc *PolicyContext) WithPolicy(yaml string) ConnectivityTest {
	// Set policyOnly flag if runner is not set
	pc.policyOnly = pc.runner == nil
	pc.ParsePolicy(yaml)
	return pc
}

// WithExpectations sets the getExpectations test result function to use during tests
func (pc *PolicyContext) WithExpectations(f GetExpectations) ConnectivityTest {
	pc.expectFunc = f
	return pc
}

// getExpectations returns the expected results for a specific test case
func (pc *PolicyContext) getExpectations(t *TestRun) (egress, ingress Result) {
	// Default to success
	if pc.expectFunc == nil {
		return ResultOK, ResultOK
	}

	egress, ingress = pc.expectFunc(t)
	if egress.Drop || ingress.Drop {
		t.Waiting("The following command is expected to fail")
	}

	return egress, ingress
}

func (pc *PolicyContext) ParsePolicy(policy string) {
	pc.CNPs, pc.err = ParsePolicyYAML(policy)
}

// ApplyPolicy returns the number of failures and a cancel function that deletes the applied policies
func (pc *PolicyContext) ApplyPolicy(ctx context.Context, c TestContext) (failures int, cancel func()) {
	if pc.err != nil {
		return 1, func() {}
	}

	return c.ApplyCNPs(ctx, false, pc.CNPs), func() {
		c.DeleteCNPs(ctx, pc.CNPs)
	}
}

// ParsePolicyYAML decodes policy yaml into a slice of CiliumNetworkPolicies
func ParsePolicyYAML(policy string) (cnps []*ciliumv2.CiliumNetworkPolicy, err error) {
	if policy == "" {
		return nil, nil
	}
	yamls := strings.Split(policy, "---")
	for _, yaml := range yamls {
		if strings.TrimSpace(yaml) == "" {
			continue
		}
		obj, groupVersionKind, err := serializer.NewCodecFactory(scheme.Scheme, serializer.EnableStrict).UniversalDeserializer().Decode([]byte(yaml), nil, nil)
		if err != nil {
			return nil, fmt.Errorf("resource decode error (%s) in: %s", err, yaml)
		}
		switch groupVersionKind.Kind {
		case "CiliumNetworkPolicy":
			cnp, ok := obj.(*ciliumv2.CiliumNetworkPolicy)
			if !ok {
				return nil, fmt.Errorf("object cast to CiliumNetworkPolicy failed: %s", yaml)
			}
			cnps = append(cnps, cnp)
		default:
			return nil, fmt.Errorf("unknown policy type '%s' in: %s", groupVersionKind.Kind, yaml)
		}
	}
	return cnps, nil
}

// DeleteCNP deletes a CNP
func (k *K8sConnectivityCheck) DeleteCNP(ctx context.Context, client k8sConnectivityImplementation, cnp *ciliumv2.CiliumNetworkPolicy) (failed bool) {
	name := client.ClusterName() + "/" + cnp.Namespace + "/" + cnp.Name
	if _, ok := k.policies[name]; !ok {
		k.Log("❌ [%s] policy was not applied, not deleting", name)
		return false
	}
	var err error
	if err = k.deleteCNP(ctx, client, cnp); err != nil {
		k.Log("❌ [%s] policy delete failed: %s", name, err)
		failed = true
	}
	delete(k.policies, name)
	return failed
}

// DeleteCNPs deletes a set of CNPs
func (k *K8sConnectivityCheck) DeleteCNPs(ctx context.Context, cnps []*ciliumv2.CiliumNetworkPolicy) {
	// bail out if nothing to do:
	if len(cnps) == 0 {
		return
	}

	startTime := time.Now()

	// Get current policy revisions in all Cilium pods
	revisions, err := k.GetCiliumPolicyRevisions(ctx)
	if err != nil {
		k.Log("❌ unable to get policy revisions for Cilium pods: %w", err)
	}
	if k.params.Verbose {
		for pc, revision := range revisions {
			k.Log("ℹ️  pod %s current policy revision %d", pc.Pod.Name, revision)
		}
	}

	var deleted []string
	for _, cnp := range cnps {
		for _, client := range k.clients.clients() {
			if k.DeleteCNP(ctx, client, cnp) {
				name := client.ClusterName() + "/" + cnp.Namespace + "/" + cnp.Name
				deleted = append(deleted, name)
			}
		}
	}

	// Wait for policies to be deleted on all Cilium nodes
	if len(deleted) > 0 {
		err = k.WaitCiliumPolicyRevisions(ctx, revisions)
		if err != nil {
			k.Log("❌ policies are not deleted in all Cilium nodes in time")
			k.CiliumLogs(ctx, startTime.Add(-1*time.Second), nil)
		} else {
			k.Log("✅ deleted CiliumNetworkPolicies: %s", strings.Join(deleted, ","))
		}
	}
}

// GetCiliumPolicyRevision returns the current policy revision in a Cilium pod
func (k *K8sConnectivityCheck) GetCiliumPolicyRevision(ctx context.Context, pc PodContext) (int, error) {
	stdout, err := pc.K8sClient.ExecInPod(ctx, pc.Pod.Namespace, pc.Pod.Name, "cilium-agent", []string{"cilium", "policy", "get", "-o", "jsonpath='{.revision}'"})
	if err != nil {
		return 0, err
	}
	revision, err := strconv.Atoi(strings.Trim(stdout.String(), "'\n"))
	if err != nil {
		return 0, fmt.Errorf("revision '%s' is not valid: %w", stdout.String(), err)
	}
	return revision, nil
}

// CiliumPolicyWaitForRevision waits for a specific policy revision to be deployed in a Cilium pod
func (k *K8sConnectivityCheck) CiliumPolicyWaitForRevision(ctx context.Context, pc PodContext, rev int, timeout time.Duration) error {
	revStr := strconv.Itoa(rev)
	timeoutStr := strconv.Itoa(int(timeout.Seconds()))
	_, err := pc.K8sClient.ExecInPod(ctx, pc.Pod.Namespace, pc.Pod.Name, "cilium-agent", []string{"cilium", "policy", "wait", revStr, "--max-wait-time", timeoutStr})
	return err
}

// GetCiliumPolicyRevisions returns the current policy revisions of all Cilium pods
func (k *K8sConnectivityCheck) GetCiliumPolicyRevisions(ctx context.Context) (map[PodContext]int, error) {
	revisions := make(map[PodContext]int)
	for _, pc := range k.ciliumPods {
		revision, err := k.GetCiliumPolicyRevision(ctx, pc)
		if err != nil {
			return revisions, err
		}
		revisions[pc] = revision
	}
	return revisions, nil
}

// WaitCiliumPolicyRevisions waits for the Cilium policy revisions to be bumped
func (k *K8sConnectivityCheck) WaitCiliumPolicyRevisions(ctx context.Context, revisions map[PodContext]int) error {
	var err error
	for pc, oldRevision := range revisions {
		err = k.CiliumPolicyWaitForRevision(ctx, pc, oldRevision+1, defaults.PolicyWaitTimeout)
		if err == nil {
			if k.params.Verbose {
				k.Log("ℹ️  [%s] pod %s revision > %d", pc.K8sClient.ClusterName(), pc.Pod.Name, oldRevision)
			}
			delete(revisions, pc)
		}
	}
	if len(revisions) == 0 {
		return nil
	}
	return err
}

// CiliumLogs logs the logs of all the Cilium agents since 'startTime' applying 'filter'
func (k *K8sConnectivityCheck) CiliumLogs(ctx context.Context, startTime time.Time, filter *regexp.Regexp) {
	for _, pc := range k.ciliumPods {
		log, err := pc.K8sClient.CiliumLogs(ctx, pc.Pod.Namespace, pc.Pod.Name, startTime, filter)
		if err != nil {
			k.Log("❌ error reading Cilium logs: %w", err)
		} else {
			k.Log("ℹ️  [%s] Cilium agent %s/%s logs since %s:\n%s", pc.K8sClient.ClusterName(), pc.Pod.Namespace, pc.Pod.Name, startTime.String(), log)
		}
	}
}

// ApplyCNPs applies policies and returns the number of failures
func (k *K8sConnectivityCheck) ApplyCNPs(ctx context.Context, policyOnly bool, cnps []*ciliumv2.CiliumNetworkPolicy) int {
	wait := false
	failures := 0
	startTime := time.Now()

	// bail out if nothing to do (nothing to delete and nothing to add):
	if (!policyOnly || policyOnly && len(k.policies) == 0) && len(cnps) == 0 {
		return 0
	}

	// Get current policy revisions in all Cilium pods
	revisions, err := k.GetCiliumPolicyRevisions(ctx)
	if err != nil {
		k.Log("❌ unable to get policy revisions for Cilium pods: %w", err)
		failures++
	}
	if k.params.Verbose {
		for pc, revision := range revisions {
			k.Log("ℹ️  pod %s current policy revision %d", pc.Pod.Name, revision)
		}
	}

	var deleted []string
	if len(cnps) == 0 {
		if policyOnly {
			k.Header("⌛ Deleting all previously applied policies...")
			for _, cnp := range k.policies {
				for _, client := range k.clients.clients() {
					name := client.ClusterName() + "/" + cnp.Namespace + "/" + cnp.Name
					deleted = append(deleted, name)
					k.DeleteCNP(ctx, client, cnp)
					wait = true
				}
			}
		}
	} else {
		k.Header("⌛ Applying CiliumNetworkPolicies...")
	}

	var applied []string
	for _, cnp := range cnps {
		var cnpJSON string
		if k.params.Verbose {
			jsn, err := json.MarshalIndent(cnp, "   ", "   ")
			if err != nil {
				k.Log("❌ Formating CNP failed: %w", err)
			} else {
				cnpJSON = string(jsn)
			}
		}
		for _, client := range k.clients.clients() {
			if cnpJSON != "" {
				k.Log("%s", cnpJSON)
				cnpJSON = ""
			}
			k8sCNP, err := k.updateOrCreateCNP(ctx, client, cnp)
			if err != nil {
				k.Log("❌ policy apply failed: %s", err)
				failures++
			} else {
				name := client.ClusterName() + "/" + cnp.Namespace + "/" + cnp.Name
				applied = append(applied, name)
				k.policies[name] = k8sCNP
				wait = true
			}
		}
	}

	if wait {
		// Wait for policies to take effect on all Cilium nodes
		err = k.WaitCiliumPolicyRevisions(ctx, revisions)
		if err != nil {
			k.Log("❌ policy is not applied in all Cilium nodes in time")
			k.CiliumLogs(ctx, startTime.Add(-1*time.Second), nil)
			failures++
			wait = false
		}
	}

	if wait {
		if len(deleted) > 0 {
			k.Log("✅ deleted CiliumNetworkPolicies: %s", strings.Join(deleted, ","))
		}
		if len(applied) > 0 {
			k.Log("✅ applied CiliumNetworkPolicies: %s", strings.Join(applied, ","))
		}
	}

	return failures
}

func (k *K8sConnectivityCheck) updateOrCreateCNP(ctx context.Context, client k8sConnectivityImplementation, cnp *ciliumv2.CiliumNetworkPolicy) (*ciliumv2.CiliumNetworkPolicy, error) {
	k8sCNP, err := client.GetCiliumNetworkPolicy(ctx, cnp.Namespace, cnp.Name, metav1.GetOptions{})
	if err == nil {
		k8sCNP.ObjectMeta.Labels = cnp.ObjectMeta.Labels
		k8sCNP.Spec = cnp.Spec
		k8sCNP.Specs = cnp.Specs
		k8sCNP.Status = ciliumv2.CiliumNetworkPolicyStatus{}
		return client.UpdateCiliumNetworkPolicy(ctx, k8sCNP, metav1.UpdateOptions{})
	}
	return client.CreateCiliumNetworkPolicy(ctx, cnp, metav1.CreateOptions{})
}

func (k *K8sConnectivityCheck) deleteCNP(ctx context.Context, client k8sConnectivityImplementation, cnp *ciliumv2.CiliumNetworkPolicy) error {
	return client.DeleteCiliumNetworkPolicy(ctx, cnp.Namespace, cnp.Name, metav1.DeleteOptions{})
}
