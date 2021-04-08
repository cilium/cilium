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
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Result int

const (
	ResultOK Result = iota
	ResultNone
	ResultDrop
	ResultL7Drop
	ResultL7Rejected
)

func (k Result) String() string {
	switch k {
	case ResultOK:
		return "OK"
	case ResultNone:
		return "None"
	case ResultDrop:
		return "Drop"
	case ResultL7Drop:
		return "L7Drop"
	case ResultL7Rejected:
		return "L7Rejected"
	default:
		return "invalid"
	}
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
}

// WithPolicyRunner sets the test runner to use and stores the policy for the tests
func (pc *PolicyContext) WithPolicyRunner(runner ConnectivityTest, yaml string) ConnectivityTest {
	pc.runner = runner
	return pc.WithPolicy(yaml)
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
	if pc.runner != nil {
		policyFailures, cleanup := pc.ApplyPolicy(ctx, c)
		c.(*K8sConnectivityCheck).policyFailures = policyFailures
		defer cleanup()

		pc.runner.Run(ctx, c)
	} else {
		failures := c.ApplyCNPs(ctx, len(pc.CNPs) == 0, pc.CNPs)
		c.Report(TestResult{
			Name:     pc.Name(),
			Failures: failures,
			Warnings: 0,
		})
	}
}

// WithPolicy sets the policy to use during tests
func (pc *PolicyContext) WithPolicy(yaml string) ConnectivityTest {
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
	if egress != ResultOK || ingress != ResultOK {
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
		obj, groupVersionKind, err := scheme.Codecs.UniversalDeserializer().Decode([]byte(yaml), nil, nil)
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
func (k *K8sConnectivityCheck) DeleteCNP(ctx context.Context, cnp *ciliumv2.CiliumNetworkPolicy) {
	name := cnp.Namespace + "/" + cnp.Name
	if err := k.deleteCNP(ctx, cnp); err != nil {
		k.Log("❌ [%s] policy delete failed: %s", name, err)
	}
	delete(k.policies, name)
}

// DeleteCNPs deletes a set of CNPs
func (k *K8sConnectivityCheck) DeleteCNPs(ctx context.Context, cnps []*ciliumv2.CiliumNetworkPolicy) {
	// bail out if nothing to do:
	if len(cnps) == 0 {
		return
	}

	// Get current policy revisions in all Cilium pods
	revisions, err := k.GetCiliumPolicyRevisions(ctx)
	if err != nil {
		k.Log("❌ unable to get policy revisions for Cilium pods: %w", err)
	}
	if k.params.Verbose {
		for pod, revision := range revisions {
			k.Log("ℹ️  pod %s current policy revision %d", pod.Name, revision)
		}
	}

	for _, cnp := range cnps {
		k.DeleteCNP(ctx, cnp)
	}

	// Wait for policies to be deleted on all Cilium nodes
	err = k.WaitCiliumPolicyRevisions(ctx, revisions)
	if err != nil {
		k.Log("❌ policies are not deleted in all Cilium nodes in time")
	}
}

// GetCiliumPolicyRevision returns the current policy revision in a Cilium pod
func (k *K8sConnectivityCheck) GetCiliumPolicyRevision(ctx context.Context, pod *corev1.Pod) (int, error) {
	stdout, err := k.clients.src.ExecInPod(ctx, pod.Namespace, pod.Name, "cilium-agent", []string{"cilium", "policy", "get", "-o", "jsonpath='{.revision}'"})
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
func (k *K8sConnectivityCheck) CiliumPolicyWaitForRevision(ctx context.Context, pod *corev1.Pod, rev int, timeout time.Duration) error {
	revStr := strconv.Itoa(rev)
	timeoutStr := strconv.Itoa(int(timeout.Seconds()))
	_, err := k.clients.src.ExecInPod(ctx, pod.Namespace, pod.Name, "cilium-agent", []string{"cilium", "policy", "wait", revStr, "--max-wait-time", timeoutStr})
	return err
}

// GetCiliumPolicyRevisions returns the current policy revisions of all Cilium pods
func (k *K8sConnectivityCheck) GetCiliumPolicyRevisions(ctx context.Context) (map[*corev1.Pod]int, error) {
	revisions := make(map[*corev1.Pod]int)
	pods, err := k.clients.src.ListPods(ctx, k.ciliumNamespace, metav1.ListOptions{LabelSelector: "k8s-app=cilium"})
	if err != nil {
		return revisions, err
	}

	for i := range pods.Items {
		// Get the address of the pod we can use as a map key
		pod := &pods.Items[i]
		revision, err := k.GetCiliumPolicyRevision(ctx, pod)
		if err != nil {
			return revisions, err
		}
		revisions[pod] = revision
	}
	return revisions, nil
}

// WaitCiliumPolicyRevisions waits for the Cilium policy revisions to be bumped
func (k *K8sConnectivityCheck) WaitCiliumPolicyRevisions(ctx context.Context, revisions map[*corev1.Pod]int) error {
	var err error
	for pod, oldRevision := range revisions {
		err = k.CiliumPolicyWaitForRevision(ctx, pod, oldRevision+1, defaults.PolicyWaitTimeout)
		if err == nil {
			if k.params.Verbose {
				k.Log("ℹ️  pod %s revision > %d", pod.Name, oldRevision)
			}
			delete(revisions, pod)
		}
	}
	if len(revisions) == 0 {
		return nil
	}
	return err
}

// ApplyCNPs applies policies and returns the number of failures
func (k *K8sConnectivityCheck) ApplyCNPs(ctx context.Context, deletePrevious bool, cnps []*ciliumv2.CiliumNetworkPolicy) int {
	wait := false
	failures := 0

	// bail out if nothing to do (nothing to delete and nothing to add):
	if (!deletePrevious || deletePrevious && len(k.policies) == 0) && len(cnps) == 0 {
		return 0
	}

	// Get current policy revisions in all Cilium pods
	revisions, err := k.GetCiliumPolicyRevisions(ctx)
	if err != nil {
		k.Log("❌ unable to get policy revisions for Cilium pods: %w", err)
		failures++
	}
	if k.params.Verbose {
		for pod, revision := range revisions {
			k.Log("ℹ️  pod %s current policy revision %d", pod.Name, revision)
		}
	}

	var deleted []string
	if deletePrevious {
		k.Header("🔌 Deleting all previously applied policies...")
		for _, cnp := range k.policies {
			name := cnp.Namespace + "/" + cnp.Name
			deleted = append(deleted, name)
			k.DeleteCNP(ctx, cnp)
			wait = true
		}
	}

	var applied []string
	for _, cnp := range cnps {
		name := cnp.Namespace + "/" + cnp.Name
		k.Header("🔌 [%s] Applying CiliumNetworkPolicy...", name)
		k8sCNP, err := k.updateOrCreateCNP(ctx, cnp)
		if err != nil {
			k.Log("❌ policy apply failed: %s", err)
			failures++
		} else {
			applied = append(applied, name)
			k.policies[name] = k8sCNP
			wait = true
		}
	}

	if wait {
		// Wait for policies to take effect on all Cilium nodes
		err = k.WaitCiliumPolicyRevisions(ctx, revisions)
		if err != nil {
			k.Log("❌ policy is not applied in all Cilium nodes in time")
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

func (k *K8sConnectivityCheck) updateOrCreateCNP(ctx context.Context, cnp *ciliumv2.CiliumNetworkPolicy) (*ciliumv2.CiliumNetworkPolicy, error) {
	k8sCNP, err := k.clients.src.GetCiliumNetworkPolicy(ctx, cnp.Namespace, cnp.Name, metav1.GetOptions{})
	if err == nil {
		k8sCNP.ObjectMeta.Labels = cnp.ObjectMeta.Labels
		k8sCNP.Spec = cnp.Spec
		k8sCNP.Specs = cnp.Specs
		k8sCNP.Status = ciliumv2.CiliumNetworkPolicyStatus{}
		return k.clients.src.UpdateCiliumNetworkPolicy(ctx, k8sCNP, metav1.UpdateOptions{})
	}
	return k.clients.src.CreateCiliumNetworkPolicy(ctx, cnp, metav1.CreateOptions{})
}

func (k *K8sConnectivityCheck) deleteCNP(ctx context.Context, cnp *ciliumv2.CiliumNetworkPolicy) error {
	return k.clients.src.DeleteCiliumNetworkPolicy(ctx, cnp.Namespace, cnp.Name, metav1.DeleteOptions{})
}
