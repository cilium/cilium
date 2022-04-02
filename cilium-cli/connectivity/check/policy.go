// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package check

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/k8s"
)

type ExitCode int16

const (
	ExitAnyError    ExitCode = -1
	ExitInvalidCode ExitCode = -2

	ExitCurlHTTPError ExitCode = 22
	ExitCurlTimeout   ExitCode = 28
)

func (e ExitCode) String() string {
	switch e {
	case ExitAnyError:
		return "any"
	case ExitInvalidCode:
		return "invalid"
	default:
		return strconv.Itoa(int(e))
	}
}

func (e ExitCode) Check(code uint8) bool {
	switch e {
	case ExitAnyError:
		return code != 0
	case ExitCode(code):
		return true
	}
	return false
}

// getCiliumPolicyRevisions returns the current policy revisions of all Cilium pods
func (ct *ConnectivityTest) getCiliumPolicyRevisions(ctx context.Context) (map[Pod]int, error) {
	revisions := make(map[Pod]int)
	for _, cp := range ct.ciliumPods {
		revision, err := getCiliumPolicyRevision(ctx, cp)
		if err != nil {
			return revisions, err
		}
		revisions[cp] = revision
	}
	return revisions, nil
}

// waitCiliumPolicyRevisions waits for the Cilium policy revisions to be bumped
// TODO: Improve error returns here, currently not possible for the caller to reliably detect timeout.
func (t *Test) waitCiliumPolicyRevisions(ctx context.Context, revisions map[Pod]int) error {
	var err error
	for pod, oldRevision := range revisions {
		err = waitCiliumPolicyRevision(ctx, pod, oldRevision+1, defaults.PolicyWaitTimeout)
		if err == nil {
			t.Debugf("Pod %s/%s revision > %d", pod.K8sClient.ClusterName(), pod.Name(), oldRevision)
			delete(revisions, pod)
		}
	}
	if len(revisions) == 0 {
		return nil
	}
	return err
}

// getCiliumPolicyRevision returns the current policy revision of a Cilium pod.
func getCiliumPolicyRevision(ctx context.Context, pod Pod) (int, error) {
	stdout, err := pod.K8sClient.ExecInPodWithTTY(ctx, pod.Pod.Namespace, pod.Pod.Name,
		defaults.AgentContainerName, []string{"cilium", "policy", "get", "-o", "jsonpath='{.revision}'"})
	if err != nil {
		return 0, err
	}
	revision, err := strconv.Atoi(strings.Trim(stdout.String(), "'\n"))
	if err != nil {
		return 0, fmt.Errorf("revision %q is not valid: %w", stdout.String(), err)
	}
	return revision, nil
}

// waitCiliumPolicyRevision waits for a Cilium pod to reach a given policy revision.
func waitCiliumPolicyRevision(ctx context.Context, pod Pod, rev int, timeout time.Duration) error {
	timeoutStr := strconv.Itoa(int(timeout.Seconds()))
	_, err := pod.K8sClient.ExecInPodWithTTY(ctx, pod.Pod.Namespace, pod.Pod.Name,
		defaults.AgentContainerName, []string{"cilium", "policy", "wait", strconv.Itoa(rev), "--max-wait-time", timeoutStr})
	return err
}

func updateOrCreateCNP(ctx context.Context, client *k8s.Client, cnp *ciliumv2.CiliumNetworkPolicy) (bool, error) {
	mod := false

	if kcnp, err := client.GetCiliumNetworkPolicy(ctx, cnp.Namespace, cnp.Name, metav1.GetOptions{}); err == nil {
		// Check if the local CNP's Spec or Specs differ from the remote version.
		//TODO(timo): What about label changes? Do they trigger a Cilium agent policy revision?
		if !kcnp.Spec.DeepEqual(cnp.Spec) ||
			!kcnp.Specs.DeepEqual(&cnp.Specs) {
			mod = true
		}

		kcnp.ObjectMeta.Labels = cnp.ObjectMeta.Labels
		kcnp.Spec = cnp.Spec
		kcnp.Specs = cnp.Specs
		kcnp.Status = ciliumv2.CiliumNetworkPolicyStatus{}

		_, err = client.UpdateCiliumNetworkPolicy(ctx, kcnp, metav1.UpdateOptions{})
		return mod, err
	}

	// Creating, so a resource will definitely be modified.
	mod = true
	_, err := client.CreateCiliumNetworkPolicy(ctx, cnp, metav1.CreateOptions{})
	return mod, err
}

// deleteCNP deletes a CiliumNetworkPolicy from the cluster.
func deleteCNP(ctx context.Context, client *k8s.Client, cnp *ciliumv2.CiliumNetworkPolicy) error {
	if err := client.DeleteCiliumNetworkPolicy(ctx, cnp.Namespace, cnp.Name, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("%s/%s/%s policy delete failed: %w", client.ClusterName(), cnp.Namespace, cnp.Name, err)
	}

	return nil
}

var (
	// ResultNone expects a successful command, don't match any packets.
	ResultNone = Result{
		None: true,
	}

	// ResultOK expects a successful command and a matching flow.
	ResultOK = Result{}

	// ResultDNSOK expects a successful command, only generating DNS traffic.
	ResultDNSOK = Result{
		DNSProxy: true,
	}

	// ResultDNSOKDropCurlTimeout expects a failed command, generating DNS traffic and a dropped flow.
	ResultDNSOKDropCurlTimeout = Result{
		DNSProxy: true,
		Drop:     true,
		ExitCode: ExitCurlTimeout,
	}

	// ResultDNSOKDropCurlHTTPError expects a failed command, generating DNS traffic and a dropped flow.
	ResultDNSOKDropCurlHTTPError = Result{
		DNSProxy: true,
		L7Proxy:  true,
		Drop:     true,
		ExitCode: ExitCurlHTTPError,
	}

	// ResultDrop expects a dropped flow and a failed command.
	ResultDrop = Result{
		Drop:     true,
		ExitCode: ExitAnyError,
	}

	// ResultDropCurlTimeout expects a dropped flow and a failed command.
	ResultDropCurlTimeout = Result{
		Drop:     true,
		ExitCode: ExitCurlTimeout,
	}

	// ResultDropCurlHTTPError expects a dropped flow and a failed command.
	ResultDropCurlHTTPError = Result{
		L7Proxy:  true,
		Drop:     true,
		ExitCode: ExitCurlHTTPError,
	}
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

	// HTTPStatus is non-zero when a HTTP status code in response is to be expected
	HTTP HTTP

	// ExitCode is the expected shell exit code
	ExitCode ExitCode
}

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
	if r.ExitCode >= 0 && r.ExitCode <= 255 {
		ret += fmt.Sprintf("-exit(%d)", r.ExitCode)
	}
	return ret
}

type ExpectationsFunc func(a *Action) (egress, ingress Result)

// WithExpectations sets the getExpectations test result function to use during tests
func (t *Test) WithExpectations(f ExpectationsFunc) *Test {
	if t.expectFunc == nil {
		t.expectFunc = f
		return t
	}

	t.Fatalf("test %s already has an expectation set", t.name)

	return nil
}

// expectations returns the expected results for a specific Action.
func (t *Test) expectations(a *Action) (egress, ingress Result) {
	// Default to success.
	if t.expectFunc == nil {
		return ResultOK, ResultOK
	}

	egress, ingress = t.expectFunc(a)
	if egress.Drop {
		t.Debugf("Expecting egress drops for Action %s: %v", a.name, egress)
	}
	if ingress.Drop {
		t.Debugf("Expecting ingress drops for Action %s: %v", a.name, ingress)
	}

	return egress, ingress
}

// addCNPs adds one or more CiliumNetworkPolicy resources to the Test.
func (t *Test) addCNPs(cnps ...*ciliumv2.CiliumNetworkPolicy) error {
	for _, p := range cnps {
		if p == nil {
			return errors.New("cannot add nil CiliumNetworkPolicy to test")
		}
		if p.Name == "" {
			return fmt.Errorf("adding CiliumNetworkPolicy with empty name to test: %v", p)
		}
		if _, ok := t.cnps[p.Name]; ok {
			return fmt.Errorf("CiliumNetworkPolicy with name %s already in test scope", p.Name)
		}

		t.cnps[p.Name] = p
	}

	return nil
}

// applyPolicies applies all the Test's registered network policies.
func (t *Test) applyPolicies(ctx context.Context) error {
	if len(t.cnps) == 0 {
		return nil
	}

	// Get current policy revisions in all Cilium pods.
	revisions, err := t.Context().getCiliumPolicyRevisions(ctx)
	if err != nil {
		return fmt.Errorf("unable to get policy revisions for Cilium pods: %w", err)
	}

	for pod, revision := range revisions {
		t.Debugf("Pod %s's current policy revision %d", pod.Name(), revision)
	}

	// Apply all given CiliumNetworkPolicies.
	var mod bool
	for _, cnp := range t.cnps {
		for _, client := range t.Context().clients.clients() {
			t.Infof("📜 Applying CiliumNetworkPolicy '%s' to namespace '%s'..", cnp.Name, cnp.Namespace)
			mod, err = updateOrCreateCNP(ctx, client, cnp)
			if err != nil {
				return fmt.Errorf("policy application failed: %w", err)
			}
		}
	}

	// Register a finalizer with the Test immediately to enable cleanup.
	// If we return a cleanup closure from this function, cleanup cannot be
	// performed if the user cancels during the policy revision wait time.
	t.finalizers = append(t.finalizers, func() error {
		// Use a detached context to make sure this call is not affected by
		// context cancellation. This deletion needs to happen event when the
		// user interrupted the program.
		if err := t.deletePolicies(context.TODO()); err != nil {
			t.ciliumLogs(ctx)
			return err
		}

		return nil
	})

	// Wait for policies to take effect on all Cilium nodes if we think policies
	// were modified on the API server.
	if mod {
		t.Debug("Policy difference detected, waiting for Cilium agents to increment policy revisions..")
		if err := t.waitCiliumPolicyRevisions(ctx, revisions); err != nil {
			return fmt.Errorf("policies were not applied on all Cilium nodes in time: %s", err)
		}
	}

	t.Debugf("📜 Successfully applied %d CiliumNetworkPolicies", len(t.cnps))

	return nil
}

// deletePolicies deletes a given set of network policies from the cluster.
func (t *Test) deletePolicies(ctx context.Context) error {
	if len(t.cnps) == 0 {
		return nil
	}

	// Get current policy revisions in all Cilium pods.
	revs, err := t.Context().getCiliumPolicyRevisions(ctx)
	if err != nil {
		return fmt.Errorf("getting policy revisions for Cilium agents: %w", err)
	}
	for pod, rev := range revs {
		t.Debugf("Pod %s's current policy revision: %d", pod.Name(), rev)
	}

	// Delete all the Test's CNPs from all clients.
	for _, cnp := range t.cnps {
		t.Infof("📜 Deleting CiliumNetworkPolicy '%s' from namespace '%s'..", cnp.Name, cnp.Namespace)
		for _, client := range t.Context().clients.clients() {
			if err := deleteCNP(ctx, client, cnp); err != nil {
				return fmt.Errorf("deleting CiliumNetworkPolicy: %w", err)
			}
		}
	}

	// Wait for policies to be deleted on all Cilium nodes.
	if err := t.waitCiliumPolicyRevisions(ctx, revs); err != nil {
		return fmt.Errorf("timed out removing policies on Cilium agents: %w", err)
	}

	t.Debugf("📜 Successfully deleted %d CiliumNetworkPolicies", len(t.cnps))

	return nil
}

// ciliumLogs dumps the logs of all Cilium agents since the start of the Test.
// filter is applied on each line of output.
func (t *Test) ciliumLogs(ctx context.Context) {
	for _, pod := range t.Context().ciliumPods {
		log, err := pod.K8sClient.CiliumLogs(ctx, pod.Pod.Namespace, pod.Pod.Name, t.startTime, nil)
		if err != nil {
			t.Fatalf("Error reading Cilium logs: %s", err)
		}
		t.Infof("Cilium agent %s/%s logs since %s:\n%s", pod.Pod.Namespace, pod.Pod.Name, t.startTime.String(), log)
	}
}

// parsePolicyYAML decodes policy yaml into a slice of CiliumNetworkPolicies.
func parsePolicyYAML(policy string) (cnps []*ciliumv2.CiliumNetworkPolicy, err error) {
	if policy == "" {
		return nil, nil
	}

	yamls := strings.Split(policy, "\n---")

	for _, yaml := range yamls {
		if strings.TrimSpace(yaml) == "" {
			continue
		}

		obj, kind, err := serializer.NewCodecFactory(scheme.Scheme, serializer.EnableStrict).UniversalDeserializer().Decode([]byte(yaml), nil, nil)
		if err != nil {
			return nil, fmt.Errorf("decoding policy yaml: %s\nerror: %w", yaml, err)
		}

		switch policy := obj.(type) {
		case *ciliumv2.CiliumNetworkPolicy:
			cnps = append(cnps, policy)
		default:
			return nil, fmt.Errorf("unknown policy type '%s' in: %s", kind.Kind, yaml)
		}
	}

	return cnps, nil
}
