// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"context"
	"fmt"
	"maps"
	"reflect"
	"strconv"
	"strings"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/k8s"
	networkingv1 "k8s.io/api/networking/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	clientsetscheme "k8s.io/client-go/kubernetes/scheme"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	"github.com/cilium/cilium/pkg/time"
)

/* How many times we should retry getting the policy revisions before
 * giving up. We want to reduce the likelihood that a connectivity blip
 * will prevent us from removing policies (dependent on revisions today)
 * because that may then cause subsequent tests to fail.
 */
const getPolicyRevisionRetries = 3

// getCiliumPolicyRevisions returns the current policy revisions of all Cilium pods
func (ct *ConnectivityTest) getCiliumPolicyRevisions(ctx context.Context) (map[Pod]int, error) {
	revisions := make(map[Pod]int)
	for _, cp := range ct.ciliumPods {
		var revision int
		var err error
		for i := 1; i <= getPolicyRevisionRetries; i++ {
			revision, err = getCiliumPolicyRevision(ctx, cp)
			if err == nil {
				break
			}
			ct.Debugf("Failed to get policy revision from pod %s (%d/%d): %w", cp, i, getPolicyRevisionRetries, err)
		}
		if err != nil {
			return revisions, err
		}
		revisions[cp] = revision
	}
	return revisions, nil
}

// waitCiliumPolicyRevisions waits for the Cilium policy revisions to be bumped
// TODO: Improve error returns here, currently not possible for the caller to reliably detect timeout.
func (t *Test) waitCiliumPolicyRevisions(ctx context.Context, revisions map[Pod]int, deltas map[string]int) error {
	var err error
	for pod, oldRevision := range revisions {
		delta := deltas[pod.K8sClient.ClusterName()]
		err = waitCiliumPolicyRevision(ctx, pod, oldRevision+delta, defaults.PolicyWaitTimeout)
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
	stdout, err := pod.K8sClient.ExecInPod(ctx, pod.Pod.Namespace, pod.Pod.Name,
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

// waitCiliumPolicyRevision waits for a Cilium pod to reach atleast a given policy revision.
func waitCiliumPolicyRevision(ctx context.Context, pod Pod, rev int, timeout time.Duration) error {
	timeoutStr := strconv.Itoa(int(timeout.Seconds()))
	_, err := pod.K8sClient.ExecInPod(ctx, pod.Pod.Namespace, pod.Pod.Name,
		defaults.AgentContainerName, []string{"cilium", "policy", "wait", strconv.Itoa(rev), "--max-wait-time", timeoutStr})
	return err
}

type policy interface {
	runtime.Object
	GetName() string
}

type client[T policy] interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (T, error)
	Create(ctx context.Context, networkPolicy T, opts metav1.CreateOptions) (T, error)
	Update(ctx context.Context, networkPolicy T, opts metav1.UpdateOptions) (T, error)
}

// CreateOrUpdatePolicy implements the generic logic to create or update a policy.
func CreateOrUpdatePolicy[T policy](ctx context.Context, client client[T], obj T, mutator func(obj T) bool) (bool, error) {
	// Let's attempt to create the policy. We optimize the creation path
	// over the update one as policies are not expected to be present.
	_, err := client.Create(ctx, obj, metav1.CreateOptions{})
	if err == nil {
		return true, nil
	}

	if !k8serrors.IsAlreadyExists(err) {
		// A real error happened.
		return false, fmt.Errorf("failed to create %T %q: %w", obj, obj.GetName(), err)
	}

	// The policy already exists, let's retrieve it.
	obj, err = client.Get(ctx, obj.GetName(), metav1.GetOptions{})
	if err != nil {
		// A real error happened.
		return false, fmt.Errorf("failed to retrieve %T %q: %w", obj, obj.GetName(), err)
	}

	// Mutate the policy. If no changes were applies, let's just return immediately.
	if !mutator(obj) {
		return false, nil
	}

	// Let's update the policy.
	_, err = client.Update(ctx, obj, metav1.UpdateOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to update k8s network policy %T %q: %w", obj, obj.GetName(), err)
	}

	return true, nil
}

// createOrUpdateCNP creates the CNP and updates it if it already exists.
func createOrUpdateCNP(ctx context.Context, client *k8s.Client, cnp *ciliumv2.CiliumNetworkPolicy) (bool, error) {
	return CreateOrUpdatePolicy(ctx, client.CiliumClientset.CiliumV2().CiliumNetworkPolicies(cnp.GetNamespace()),
		cnp, func(current *ciliumv2.CiliumNetworkPolicy) bool {
			if maps.Equal(current.GetLabels(), cnp.GetLabels()) &&
				current.Spec.DeepEqual(cnp.Spec) &&
				current.Specs.DeepEqual(&cnp.Specs) {
				return false
			}

			current.ObjectMeta.Labels = cnp.ObjectMeta.Labels
			current.Spec = cnp.Spec
			current.Specs = cnp.Specs
			return true
		},
	)
}

// createOrUpdateCCNP creates the CCNP and updates it if it already exists.
func createOrUpdateCCNP(ctx context.Context, client *k8s.Client, ccnp *ciliumv2.CiliumClusterwideNetworkPolicy) (bool, error) {
	return CreateOrUpdatePolicy(ctx, client.CiliumClientset.CiliumV2().CiliumClusterwideNetworkPolicies(),
		ccnp, func(current *ciliumv2.CiliumClusterwideNetworkPolicy) bool {
			if maps.Equal(current.GetLabels(), ccnp.GetLabels()) &&
				current.Spec.DeepEqual(ccnp.Spec) &&
				current.Specs.DeepEqual(&ccnp.Specs) {
				return false
			}

			current.ObjectMeta.Labels = ccnp.ObjectMeta.Labels
			current.Spec = ccnp.Spec
			current.Specs = ccnp.Specs
			return true
		},
	)
}

// createOrUpdateKNP creates the KNP and updates it if it already exists.
func createOrUpdateKNP(ctx context.Context, client *k8s.Client, knp *networkingv1.NetworkPolicy) (bool, error) {
	return CreateOrUpdatePolicy(ctx, client.Clientset.NetworkingV1().NetworkPolicies(knp.GetNamespace()),
		knp, func(current *networkingv1.NetworkPolicy) bool {
			if maps.Equal(current.GetLabels(), knp.GetLabels()) &&
				reflect.DeepEqual(current.Spec, knp.Spec) {
				return false
			}

			current.ObjectMeta.Labels = knp.ObjectMeta.Labels
			current.Spec = knp.Spec
			return true
		},
	)
}

// createOrUpdateCEGP creates the CEGP and updates it if it already exists.
func createOrUpdateCEGP(ctx context.Context, client *k8s.Client, cegp *ciliumv2.CiliumEgressGatewayPolicy) error {
	_, err := CreateOrUpdatePolicy(ctx, client.CiliumClientset.CiliumV2().CiliumEgressGatewayPolicies(),
		cegp, func(current *ciliumv2.CiliumEgressGatewayPolicy) bool {
			if maps.Equal(current.GetLabels(), cegp.GetLabels()) &&
				current.Spec.DeepEqual(&cegp.Spec) {
				return false
			}

			current.ObjectMeta.Labels = cegp.ObjectMeta.Labels
			current.Spec = cegp.Spec
			return true
		},
	)
	return err
}

// deleteCNP deletes a CiliumNetworkPolicy from the cluster.
func deleteCNP(ctx context.Context, client *k8s.Client, cnp *ciliumv2.CiliumNetworkPolicy) error {
	if err := client.DeleteCiliumNetworkPolicy(ctx, cnp.Namespace, cnp.Name, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("%s/%s/%s policy delete failed: %w", client.ClusterName(), cnp.Namespace, cnp.Name, err)
	}

	return nil
}

// deleteCNP deletes a CiliumNetworkPolicy from the cluster.
func deleteCCNP(ctx context.Context, client *k8s.Client, ccnp *ciliumv2.CiliumClusterwideNetworkPolicy) error {
	if err := client.DeleteCiliumClusterwideNetworkPolicy(ctx, ccnp.Name, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("%s/%s policy delete failed: %w", client.ClusterName(), ccnp.Name, err)
	}

	return nil
}

// deleteKNP deletes a Kubernetes NetworkPolicy from the cluster.
func deleteKNP(ctx context.Context, client *k8s.Client, knp *networkingv1.NetworkPolicy) error {
	if err := client.DeleteKubernetesNetworkPolicy(ctx, knp.Namespace, knp.Name, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("%s/%s/%s policy delete failed: %w", client.ClusterName(), knp.Namespace, knp.Name, err)
	}

	return nil
}

// deleteCEGP deletes a CiliumEgressGatewayPolicy from the cluster.
func deleteCEGP(ctx context.Context, client *k8s.Client, cegp *ciliumv2.CiliumEgressGatewayPolicy) error {
	if err := client.DeleteCiliumEgressGatewayPolicy(ctx, cegp.Name, metav1.DeleteOptions{}); err != nil {
		return fmt.Errorf("%s/%s policy delete failed: %w", client.ClusterName(), cegp.Name, err)
	}

	return nil
}

func defaultDropReason(flow *flowpb.Flow) bool {
	return flow.GetDropReasonDesc() != flowpb.DropReason_DROP_REASON_UNKNOWN
}

func policyDenyReason(flow *flowpb.Flow) bool {
	return flow.GetDropReasonDesc() == flowpb.DropReason_POLICY_DENY
}

func defaultDenyReason(flow *flowpb.Flow) bool {
	return flow.GetDropReasonDesc() == flowpb.DropReason_POLICY_DENIED
}

func authRequiredDropReason(flow *flowpb.Flow) bool {
	return flow.GetDropReasonDesc() == flowpb.DropReason_AUTH_REQUIRED
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
		DNSProxy:       true,
		Drop:           true,
		DropReasonFunc: defaultDropReason,
		ExitCode:       ExitCurlTimeout,
	}

	// ResultDNSOKDropCurlHTTPError expects a failed command, generating DNS traffic and a dropped flow.
	ResultDNSOKDropCurlHTTPError = Result{
		DNSProxy:       true,
		L7Proxy:        true,
		Drop:           true,
		DropReasonFunc: defaultDropReason,
		ExitCode:       ExitCurlHTTPError,
	}

	// ResultCurlHTTPError expects a failed command, but no dropped flow or DNS proxy.
	ResultCurlHTTPError = Result{
		L7Proxy:        true,
		Drop:           false,
		DropReasonFunc: defaultDropReason,
		ExitCode:       ExitCurlHTTPError,
	}

	// ResultDrop expects a dropped flow and a failed command.
	ResultDrop = Result{
		Drop:           true,
		ExitCode:       ExitAnyError,
		DropReasonFunc: defaultDropReason,
	}

	// ResultDropAuthRequired expects a dropped flow with auth required as reason.
	ResultDropAuthRequired = Result{
		Drop:           true,
		DropReasonFunc: authRequiredDropReason,
	}

	// ResultAnyReasonEgressDrop expects a dropped flow at Egress and a failed command.
	ResultAnyReasonEgressDrop = Result{
		Drop:           true,
		DropReasonFunc: defaultDropReason,
		EgressDrop:     true,
		ExitCode:       ExitAnyError,
	}

	// ResultPolicyDenyEgressDrop expects a dropped flow at Egress due to policy deny and a failed command.
	ResultPolicyDenyEgressDrop = Result{
		Drop:           true,
		DropReasonFunc: policyDenyReason,
		EgressDrop:     true,
		ExitCode:       ExitAnyError,
	}

	// ResultDefaultDenyEgressDrop expects a dropped flow at Egress due to default deny and a failed command.
	ResultDefaultDenyEgressDrop = Result{
		Drop:           true,
		DropReasonFunc: defaultDenyReason,
		EgressDrop:     true,
		ExitCode:       ExitAnyError,
	}

	// ResultIngressAnyReasonDrop expects a dropped flow at Ingress and a failed command.
	ResultIngressAnyReasonDrop = Result{
		Drop:           true,
		IngressDrop:    true,
		DropReasonFunc: defaultDropReason,
		ExitCode:       ExitAnyError,
	}

	// ResultPolicyDenyIngressDrop expects a dropped flow at Ingress due to policy deny reason and a failed command.
	ResultPolicyDenyIngressDrop = Result{
		Drop:           true,
		IngressDrop:    true,
		DropReasonFunc: policyDenyReason,
		ExitCode:       ExitAnyError,
	}

	// ResultDefaultDenyIngressDrop expects a dropped flow at Ingress due to default deny reason and a failed command.
	ResultDefaultDenyIngressDrop = Result{
		Drop:           true,
		IngressDrop:    true,
		DropReasonFunc: defaultDenyReason,
		ExitCode:       ExitAnyError,
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

func RegisterPolicy[T policy](current map[string]T, policies ...T) (map[string]T, error) {
	for _, p := range policies {
		if p.GetName() == "" {
			return current, fmt.Errorf("adding %T with empty name to test: %v", p, p)
		}
		if _, ok := current[p.GetName()]; ok {
			return current, fmt.Errorf("%T with name %s already in test scope", p, p.GetName())
		}

		current[p.GetName()] = p
	}

	return current, nil
}

// addCNPs adds one or more CiliumNetworkPolicy resources to the Test.
func (t *Test) addCNPs(cnps ...*ciliumv2.CiliumNetworkPolicy) (err error) {
	t.cnps, err = RegisterPolicy(t.cnps, cnps...)
	return err
}

// addCNPs adds one or more CiliumClusterwideNetworkPolicy resources to the Test.
func (t *Test) addCCNPs(ccnps ...*ciliumv2.CiliumClusterwideNetworkPolicy) (err error) {
	t.ccnps, err = RegisterPolicy(t.ccnps, ccnps...)
	return err
}

// addKNPs adds one or more K8S NetworkPolicy resources to the Test.
func (t *Test) addKNPs(policies ...*networkingv1.NetworkPolicy) (err error) {
	t.knps, err = RegisterPolicy(t.knps, policies...)
	return err
}

// addCEGPs adds one or more CiliumEgressGatewayPolicy resources to the Test.
func (t *Test) addCEGPs(cegps ...*ciliumv2.CiliumEgressGatewayPolicy) (err error) {
	t.cegps, err = RegisterPolicy(t.cegps, cegps...)
	return err
}

func sumMap(m map[string]int) int {
	sum := 0
	for _, v := range m {
		sum += v
	}
	return sum
}

// applyPolicies applies all the Test's registered network policies.
func (t *Test) applyPolicies(ctx context.Context) error {
	if len(t.cnps) == 0 && len(t.ccnps) == 0 && len(t.knps) == 0 && len(t.cegps) == 0 {
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

	// Incremented, by cluster, for every expected revision.
	revDeltas := map[string]int{}
	// Apply all given CiliumNetworkPolicies.
	for _, cnp := range t.cnps {
		for _, client := range t.Context().clients.clients() {
			t.Infof("📜 Applying CiliumNetworkPolicy '%s' to namespace '%s'..", cnp.Name, cnp.Namespace)
			changed, err := createOrUpdateCNP(ctx, client, cnp)
			if err != nil {
				return fmt.Errorf("policy application failed: %w", err)
			}
			if changed {
				revDeltas[client.ClusterName()]++
			}
		}
	}

	// Apply all given CiliumClusterwideNetworkPolicy.
	for _, ccnp := range t.ccnps {
		for _, client := range t.Context().clients.clients() {
			t.Infof("📜 Applying CiliumClusterwideNetworkPolicy '%s'..", ccnp.Name)
			changed, err := createOrUpdateCCNP(ctx, client, ccnp)
			if err != nil {
				return fmt.Errorf("policy application failed: %w", err)
			}
			if changed {
				revDeltas[client.ClusterName()]++
			}
		}
	}

	// Apply all given Kubernetes Network Policies.
	for _, knp := range t.knps {
		for _, client := range t.Context().clients.clients() {
			t.Infof("📜 Applying KubernetesNetworkPolicy '%s' to namespace '%s'..", knp.Name, knp.Namespace)
			changed, err := createOrUpdateKNP(ctx, client, knp)
			if err != nil {
				return fmt.Errorf("policy application failed: %w", err)
			}
			if changed {
				revDeltas[client.ClusterName()]++
			}
		}
	}

	// Apply all given Cilium Egress Gateway Policies.
	for _, cegp := range t.cegps {
		for _, client := range t.Context().clients.clients() {
			t.Infof("📜 Applying CiliumEgressGatewayPolicy '%s' to namespace '%s'..", cegp.Name, cegp.Namespace)
			if err := createOrUpdateCEGP(ctx, client, cegp); err != nil {
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
			t.CiliumLogs(ctx)
			return err
		}

		return nil
	})

	// Wait for policies to take effect on all Cilium nodes if we think policies
	// were modified on the API server.
	//
	// Note that this doesn't wait for CiliumEgressGatewayPolicies, so it will
	// be up the individual tests to ensure that policies are actually
	// enforced (i.e. BPF entries in the policy map are set).
	if sumMap(revDeltas) > 0 {
		t.Debug("Policy difference detected, waiting for Cilium agents to increment policy revisions..")
		if err := t.waitCiliumPolicyRevisions(ctx, revisions, revDeltas); err != nil {
			return fmt.Errorf("policies were not applied on all Cilium nodes in time: %s", err)
		}
	}

	if len(t.cnps) > 0 {
		t.Debugf("📜 Successfully applied %d CiliumNetworkPolicies", len(t.cnps))
	}
	if len(t.ccnps) > 0 {
		t.Debugf("📜 Successfully applied %d CiliumClusterwideNetworkPolicies", len(t.ccnps))
	}
	if len(t.knps) > 0 {
		t.Debugf("📜 Successfully applied %d K8S NetworkPolicies", len(t.knps))
	}
	if len(t.cegps) > 0 {
		t.Debugf("📜 Successfully applied %d CiliumEgressGatewayPolicies", len(t.cegps))
	}

	return nil
}

// deletePolicies deletes a given set of network policies from the cluster.
func (t *Test) deletePolicies(ctx context.Context) error {
	if len(t.cnps) == 0 && len(t.ccnps) == 0 && len(t.knps) == 0 && len(t.cegps) == 0 {
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

	revDeltas := map[string]int{}
	// Delete all the Test's CNPs from all clients.
	for _, cnp := range t.cnps {
		t.Infof("📜 Deleting CiliumNetworkPolicy '%s' from namespace '%s'..", cnp.Name, cnp.Namespace)
		for _, client := range t.Context().clients.clients() {
			if err := deleteCNP(ctx, client, cnp); err != nil {
				return fmt.Errorf("deleting CiliumNetworkPolicy: %w", err)
			}
			revDeltas[client.ClusterName()]++
		}
	}

	// Delete all the Test's CCNPs from all clients.
	for _, ccnp := range t.ccnps {
		t.Infof("📜 Deleting CiliumClusterwideNetworkPolicy '%s'..", ccnp.Name)
		for _, client := range t.Context().clients.clients() {
			if err := deleteCCNP(ctx, client, ccnp); err != nil {
				return fmt.Errorf("deleting CiliumClusterwideNetworkPolicy: %w", err)
			}
			revDeltas[client.ClusterName()]++
		}
	}

	// Delete all the Test's KNPs from all clients.
	for _, knp := range t.knps {
		t.Infof("📜 Deleting K8S NetworkPolicy '%s' from namespace '%s'..", knp.Name, knp.Namespace)
		for _, client := range t.Context().clients.clients() {
			if err := deleteKNP(ctx, client, knp); err != nil {
				return fmt.Errorf("deleting K8S NetworkPolicy: %w", err)
			}
			revDeltas[client.ClusterName()]++
		}
	}

	// Delete all the Test's CEGPs from all clients.
	for _, cegp := range t.cegps {
		t.Infof("📜 Deleting CiliumEgressGatewayPolicy '%s' from namespace '%s'..", cegp.Name, cegp.Namespace)
		for _, client := range t.Context().clients.clients() {
			if err := deleteCEGP(ctx, client, cegp); err != nil {
				return fmt.Errorf("deleting CiliumEgressGatewayPolicy: %w", err)
			}
		}
	}

	if len(t.cnps) != 0 || len(t.ccnps) != 0 || len(t.knps) != 0 {
		// Wait for policies to be deleted on all Cilium nodes.
		if err := t.waitCiliumPolicyRevisions(ctx, revs, revDeltas); err != nil {
			return fmt.Errorf("timed out removing policies on Cilium agents: %w", err)
		}
	}

	if len(t.cnps) > 0 {
		t.Debugf("📜 Successfully deleted %d CiliumNetworkPolicies", len(t.cnps))
	}

	if len(t.ccnps) > 0 {
		t.Debugf("📜 Successfully deleted %d CiliumClusterwideNetworkPolicies", len(t.ccnps))
	}

	if len(t.knps) > 0 {
		t.Debugf("📜 Successfully deleted %d K8S NetworkPolicy", len(t.knps))
	}

	if len(t.cegps) > 0 {
		t.Debugf("📜 Successfully deleted %d CiliumEgressGatewayPolicies", len(t.cegps))
	}

	return nil
}

// CiliumLogs dumps the logs of all Cilium agents since the start of the Test.
// filter is applied on each line of output.
func (t *Test) CiliumLogs(ctx context.Context) {
	for _, pod := range t.Context().ciliumPods {
		log, err := pod.K8sClient.CiliumLogs(ctx, pod.Pod.Namespace, pod.Pod.Name, t.startTime, nil)
		if err != nil {
			t.Fatalf("Error reading Cilium logs: %s", err)
		}
		t.Infof("Cilium agent %s/%s logs since %s:\n%s", pod.Pod.Namespace, pod.Pod.Name, t.startTime.String(), log)
	}
}

// ParsePolicyYAML decodes a yaml file into a slice of policies.
func ParsePolicyYAML[T runtime.Object](input string, scheme *runtime.Scheme) (output []T, err error) {
	if input == "" {
		return nil, nil
	}

	yamls := strings.Split(input, "\n---")

	for _, yaml := range yamls {
		if strings.TrimSpace(yaml) == "" {
			continue
		}

		obj, kind, err := serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDeserializer().Decode([]byte(yaml), nil, nil)
		if err != nil {
			return nil, fmt.Errorf("decoding yaml file: %s\nerror: %w", yaml, err)
		}

		switch policy := obj.(type) {
		case T:
			output = append(output, policy)
		default:
			return nil, fmt.Errorf("unknown type '%s' in: %s", kind.Kind, yaml)
		}
	}

	return output, nil
}

// parseCiliumPolicyYAML decodes policy yaml into a slice of CiliumNetworkPolicies.
func parseCiliumPolicyYAML(policy string) (cnps []*ciliumv2.CiliumNetworkPolicy, err error) {
	return ParsePolicyYAML[*ciliumv2.CiliumNetworkPolicy](policy, scheme.Scheme)
}

// parseCiliumClusterwidePolicyYAML decodes policy yaml into a slice of CiliumClusterwideNetworkPolicy.
func parseCiliumClusterwidePolicyYAML(policy string) (cnps []*ciliumv2.CiliumClusterwideNetworkPolicy, err error) {
	return ParsePolicyYAML[*ciliumv2.CiliumClusterwideNetworkPolicy](policy, scheme.Scheme)
}

// parseK8SPolicyYAML decodes policy yaml into a slice of K8S NetworkPolicies.
func parseK8SPolicyYAML(policy string) (policies []*networkingv1.NetworkPolicy, err error) {
	return ParsePolicyYAML[*networkingv1.NetworkPolicy](policy, clientsetscheme.Scheme)
}

// parseCiliumEgressGatewayPolicyYAML decodes policy yaml into a slice of
// CiliumEgressGatewayPolicies.
func parseCiliumEgressGatewayPolicyYAML(policy string) (cegps []*ciliumv2.CiliumEgressGatewayPolicy, err error) {
	return ParsePolicyYAML[*ciliumv2.CiliumEgressGatewayPolicy](policy, scheme.Scheme)
}
