// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	logfilter "github.com/cilium/cilium/cilium-cli/utils/log"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy/api"
)

/* How many times we should retry getting the policy revisions before
 * giving up. We want to reduce the likelihood that a connectivity blip
 * will prevent us from removing policies (dependent on revisions today)
 * because that may then cause subsequent tests to fail.
 */
const getPolicyRevisionRetries = 3

const policyBumpAnnotation = "cli.cilium.io/bump-policy"

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

// createOrUpdate applies a generic object to the cluster, returning true if it was updated
func createOrUpdate(ctx context.Context, client *k8s.Client, obj k8s.Object) (bool, error) {
	existing, err := client.GetGeneric(ctx, obj.GetNamespace(), obj.GetName(), obj)
	if err != nil && !k8serrors.IsNotFound(err) {
		return false, fmt.Errorf("failed to retrieve %s/%s: %w", obj.GetNamespace(), obj.GetName(), err)
	}

	created, err := client.ApplyGeneric(ctx, obj)
	if err != nil {
		return false, fmt.Errorf("failed to create / update %s %s/%s: %w", obj.GetObjectKind().GroupVersionKind().Kind, obj.GetNamespace(), obj.GetName(), err)
	}

	if existing == nil {
		return true, nil
	}

	return existing.GetGeneration() != created.GetGeneration(), nil
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

func unencryptedDropReason(flow *flowpb.Flow) bool {
	return flow.GetDropReasonDesc() == flowpb.DropReason_UNENCRYPTED_TRAFFIC
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

func sumMap(m map[string]int) int {
	sum := 0
	for _, v := range m {
		sum += v
	}
	return sum
}

// policyApplyDeleteLock guarantees that only one connectivity test instance
// can apply or delete policies in case of connectivity test concurrency > 1
var policyApplyDeleteLock = lock.Mutex{}

// isPolicy returns true if the object is a network policy, and thus
// should bump the policy revision.
//
// This is true if the object is a known policy type (CNP / CCNP / KNP)
// or if the object has the annotation cli.cilium.io/bump-policy
func isPolicy(obj k8s.Object) bool {
	if _, ok := obj.GetAnnotations()[policyBumpAnnotation]; ok {
		return true
	}
	gk := obj.GetObjectKind().GroupVersionKind().GroupKind()
	return (gk == schema.GroupKind{Group: ciliumv2.CustomResourceDefinitionGroup, Kind: ciliumv2.CNPKindDefinition} ||
		gk == schema.GroupKind{Group: ciliumv2.CustomResourceDefinitionGroup, Kind: ciliumv2.CCNPKindDefinition} ||
		gk == schema.GroupKind{Group: networkingv1.GroupName, Kind: "NetworkPolicy"})
}

// applyResources applies all the Test's registered additional resources
func (t *Test) applyResources(ctx context.Context) error {
	if len(t.resources) == 0 {
		return nil
	}

	policyApplyDeleteLock.Lock()
	defer policyApplyDeleteLock.Unlock()

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

	// apply resources to all clusters
	for _, obj := range t.resources {
		kind := obj.GetObjectKind().GroupVersionKind().Kind
		for _, client := range t.Context().clients.clients() {
			t.Infof("📜 Applying %s '%s' to namespace '%s' on cluster %s..", kind, obj.GetName(), obj.GetNamespace(), client.ClusterName())
			changed, err := createOrUpdate(ctx, client, obj)
			if err != nil {
				return fmt.Errorf("failed to apply %s '%s' to namespace '%s' on cluster %s: %w", kind, obj.GetName(), obj.GetNamespace(), client.ClusterName(), err)
			}

			if changed && isPolicy(obj) {
				revDeltas[client.ClusterName()]++
			}
		}
	}

	// Register a finalizer with the Test immediately to enable cleanup.
	// If we return a cleanup closure from this function, cleanup cannot be
	// performed if the user cancels during the policy revision wait time.
	t.finalizers = append(t.finalizers, func(ctx context.Context) error {
		if err := t.deleteResources(ctx); err != nil {
			t.ContainerLogs(ctx)
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
			return fmt.Errorf("policies were not applied on all Cilium nodes in time: %w", err)
		}
	}

	if len(t.resources) > 0 {
		t.Debugf("📜 Successfully applied %d additional resources", len(t.resources))
	}

	return nil
}

// deleteResources deletes the previously-created set of resources that
// belong to this test.
func (t *Test) deleteResources(ctx context.Context) error {
	if len(t.resources) == 0 {
		return nil
	}

	policyApplyDeleteLock.Lock()
	defer policyApplyDeleteLock.Unlock()

	// Get current policy revisions in all Cilium pods.
	revs, err := t.Context().getCiliumPolicyRevisions(ctx)
	if err != nil {
		return fmt.Errorf("getting policy revisions for Cilium agents: %w", err)
	}
	for pod, rev := range revs {
		t.Debugf("Pod %s's current policy revision: %d", pod.Name(), rev)
	}

	revDeltas := map[string]int{}
	for _, obj := range t.resources {
		kind := obj.GetObjectKind().GroupVersionKind().Kind
		for _, client := range t.Context().clients.clients() {
			t.Infof("📜 Deleting %s '%s' in namespace '%s' on cluster %s..", kind, obj.GetName(), obj.GetNamespace(), client.ClusterName())
			err := client.DeleteGeneric(ctx, obj)
			if err != nil {
				return fmt.Errorf("failed to delete %s '%s' in namespace '%s' on cluster %s: %w", kind, obj.GetName(), obj.GetNamespace(), client.ClusterName(), err)
			}

			if isPolicy(obj) {
				revDeltas[client.ClusterName()]++
			}
		}
	}

	if len(revDeltas) > 0 {
		// Wait for policies to be deleted on all Cilium nodes.
		if err := t.waitCiliumPolicyRevisions(ctx, revs, revDeltas); err != nil {
			return fmt.Errorf("timed out waiting for policy updates to be processed on Cilium agents: %w", err)
		}
	}

	if len(t.resources) > 0 {
		t.Debugf("📜 Successfully deleted %d resources", len(t.resources))
	}

	return nil
}

// ContainerLogs dumps the logs of all Cilium agents since the start of the Test.
// filter is applied on each line of output.
func (t *Test) ContainerLogs(ctx context.Context) {
	for _, pod := range t.Context().ciliumPods {
		log, err := pod.K8sClient.ContainerLogs(ctx, pod.Pod.Namespace, pod.Pod.Name, defaults.AgentContainerName, t.startTime, false)
		if err != nil {
			t.Fatalf("Error reading Cilium logs: %s", err)
		}
		t.Infof(
			"Cilium agent %s/%s logs since %s:\n%s",
			pod.Pod.Namespace,
			pod.Pod.Name,
			t.startTime.String(),
			logfilter.Reduce(log, t.verbose),
		)
	}
}

// tweakPolicy adjusts a test-dependent resource to insert the namespace
// in known objects.
func (t *Test) tweakPolicy(in *unstructured.Unstructured) *unstructured.Unstructured {
	group := in.GroupVersionKind().Group
	kind := in.GroupVersionKind().Kind

	var tweaked runtime.Object
	if group == ciliumv2.CustomResourceDefinitionGroup && kind == ciliumv2.CNPKindDefinition {
		t.WithFeatureRequirements(features.RequireEnabled(features.CNP))
		cnp := ciliumv2.CiliumNetworkPolicy{}
		if err := convertInto(in, &cnp); err != nil {
			t.Fatalf("could not parse CiliumNetworkPolicy: %v", err)
			return nil
		}
		if cnp.Namespace == "" {
			cnp.Namespace = t.ctx.params.TestNamespace
		}
		configureNamespaceInPolicySpec(cnp.Spec, t.ctx.params.TestNamespace)
		tweaked = &cnp
	}

	if group == ciliumv2.CustomResourceDefinitionGroup && kind == ciliumv2.CCNPKindDefinition {
		t.WithFeatureRequirements(features.RequireEnabled(features.CCNP))
		ccnp := ciliumv2.CiliumClusterwideNetworkPolicy{}
		if err := convertInto(in, &ccnp); err != nil {
			t.Fatalf("could not parse CiliumClusterwideNetworkPolicy: %v", err)
			return nil
		}
		configureNamespaceInPolicySpec(ccnp.Spec, t.ctx.params.TestNamespace)
		tweaked = &ccnp
	}

	if group == networkingv1.GroupName && kind == "NetworkPolicy" {
		t.WithFeatureRequirements(features.RequireEnabled(features.KNP))
		knp := networkingv1.NetworkPolicy{}
		if err := convertInto(in, &knp); err != nil {
			t.Fatalf("could not parse NetworkPolicy: %v", err)
			return nil
		}
		configureNamespaceInKNP(&knp, t.ctx.params.TestNamespace)
		tweaked = &knp
	}

	if tweaked == nil {
		return in
	}

	out := unstructured.Unstructured{}
	if err := convertInto(tweaked, &out); err != nil {
		t.Fatalf("could not convert tweaked object") // unreachable
		return nil
	}
	return &out
}

func configureNamespaceInPolicySpec(spec *api.Rule, namespace string) {
	if spec == nil {
		return
	}

	for _, k := range []string{
		k8sConst.PodNamespaceLabel,
		KubernetesSourcedLabelPrefix + k8sConst.PodNamespaceLabel,
		AnySourceLabelPrefix + k8sConst.PodNamespaceLabel,
	} {
		for _, e := range spec.Egress {
			for _, es := range e.ToEndpoints {
				if n, ok := es.MatchLabels[k]; ok && n == defaults.ConnectivityCheckNamespace {
					es.MatchLabels[k] = namespace
				}
			}
		}
		for _, e := range spec.Ingress {
			for _, es := range e.FromEndpoints {
				if n, ok := es.MatchLabels[k]; ok && n == defaults.ConnectivityCheckNamespace {
					es.MatchLabels[k] = namespace
				}
			}
		}

		for _, e := range spec.EgressDeny {
			for _, es := range e.ToEndpoints {
				if n, ok := es.MatchLabels[k]; ok && n == defaults.ConnectivityCheckNamespace {
					es.MatchLabels[k] = namespace
				}
			}
		}

		for _, e := range spec.IngressDeny {
			for _, es := range e.FromEndpoints {
				if n, ok := es.MatchLabels[k]; ok && n == defaults.ConnectivityCheckNamespace {
					es.MatchLabels[k] = namespace
				}
			}
		}
	}
}

func configureNamespaceInKNP(pol *networkingv1.NetworkPolicy, namespace string) {
	pol.Namespace = namespace

	if pol.Spec.Size() != 0 {
		for _, k := range []string{
			k8sConst.PodNamespaceLabel,
			KubernetesSourcedLabelPrefix + k8sConst.PodNamespaceLabel,
			AnySourceLabelPrefix + k8sConst.PodNamespaceLabel,
		} {
			for _, e := range pol.Spec.Egress {
				for _, es := range e.To {
					if es.PodSelector != nil {
						if n, ok := es.PodSelector.MatchLabels[k]; ok && n == defaults.ConnectivityCheckNamespace {
							es.PodSelector.MatchLabels[k] = namespace
						}
					}
					if es.NamespaceSelector != nil {
						if n, ok := es.NamespaceSelector.MatchLabels[k]; ok && n == defaults.ConnectivityCheckNamespace {
							es.NamespaceSelector.MatchLabels[k] = namespace
						}
					}
				}
			}
			for _, e := range pol.Spec.Ingress {
				for _, es := range e.From {
					if es.PodSelector != nil {
						if n, ok := es.PodSelector.MatchLabels[k]; ok && n == defaults.ConnectivityCheckNamespace {
							es.PodSelector.MatchLabels[k] = namespace
						}
					}
					if es.NamespaceSelector != nil {
						if n, ok := es.NamespaceSelector.MatchLabels[k]; ok && n == defaults.ConnectivityCheckNamespace {
							es.NamespaceSelector.MatchLabels[k] = namespace
						}
					}
				}
			}
		}
	}
}

// convertInto converts an object using JSON
func convertInto(input, output runtime.Object) error {
	b, err := json.Marshal(input)
	if err != nil {
		return err // unreachable
	}
	return parseInto(b, output)
}

func parseInto(b []byte, output runtime.Object) error {
	_, _, err := serializer.NewCodecFactory(scheme.Scheme, serializer.EnableStrict).UniversalDeserializer().Decode(b, nil, output)
	return err
}
