// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package groups

import (
	"context"
	"fmt"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
)

const (
	cnpKindName = "derivative"
	parentCNP   = "io.cilium.network.policy.parent.uuid"
	cnpKindKey  = "io.cilium.network.policy.kind"
)

func getDerivativeName(obj v1.Object) string {
	return fmt.Sprintf("%s-togroups-%s",
		obj.GetName(),
		obj.GetUID())
}

// createDerivativeCNP will return a new CNP based on the given rule.
func createDerivativeCNP(ctx context.Context, cnp *cilium_v2.CiliumNetworkPolicy) (*cilium_v2.CiliumNetworkPolicy, error) {
	// CNP informer may provide a CNP object without APIVersion or Kind.
	// Setting manually to make sure that the derivative policy works ok.
	derivativeCNP := &cilium_v2.CiliumNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:      getDerivativeName(cnp),
			Namespace: cnp.ObjectMeta.Namespace,
			OwnerReferences: []v1.OwnerReference{{
				APIVersion: cilium_v2.SchemeGroupVersion.String(),
				Kind:       cilium_v2.CNPKindDefinition,
				Name:       cnp.ObjectMeta.Name,
				UID:        cnp.ObjectMeta.UID,
			}},
			Labels: map[string]string{
				parentCNP:  string(cnp.ObjectMeta.UID),
				cnpKindKey: cnpKindName,
			},
		},
	}

	var (
		rules api.Rules
		err   error
	)

	rules, err = cnp.Parse()

	if err != nil {
		// We return a valid pointer for derivative policy here instead of nil.
		// This object is used to get generated name for the derivative policy
		// when updating the status of the network policy.
		return derivativeCNP, fmt.Errorf("cannot parse CNP: %v", err)
	}

	derivativeCNP.Specs, err = createAPIRules(ctx, rules)

	return derivativeCNP, err
}

// createDerivativeCCNP will return a new CCNP based on the given rule.
func createDerivativeCCNP(ctx context.Context, cnp *cilium_v2.CiliumNetworkPolicy) (*cilium_v2.CiliumClusterwideNetworkPolicy, error) {
	ccnp := &cilium_v2.CiliumClusterwideNetworkPolicy{
		TypeMeta:   cnp.TypeMeta,
		ObjectMeta: cnp.ObjectMeta,
		Spec:       cnp.Spec,
		Specs:      cnp.Specs,
		Status:     cnp.Status,
	}

	// CCNP informer may provide a CCNP object without APIVersion or Kind.
	// Setting manually to make sure that the derivative policy works ok.
	derivativeCCNP := &cilium_v2.CiliumClusterwideNetworkPolicy{
		ObjectMeta: v1.ObjectMeta{
			Name:      getDerivativeName(ccnp),
			Namespace: ccnp.ObjectMeta.Namespace,
			OwnerReferences: []v1.OwnerReference{{
				APIVersion: cilium_v2.SchemeGroupVersion.String(),
				Kind:       cilium_v2.CCNPKindDefinition,
				Name:       ccnp.ObjectMeta.Name,
				UID:        ccnp.ObjectMeta.UID,
			}},
			Labels: map[string]string{
				parentCNP:  string(ccnp.ObjectMeta.UID),
				cnpKindKey: cnpKindName,
			},
		},
	}

	var (
		rules api.Rules
		err   error
	)

	rules, err = ccnp.Parse()

	if err != nil {
		// We return a valid pointer for derivative policy here instead of nil.
		// This object is used to get generated name for the derivative policy
		// when updating the status of the network policy.
		return derivativeCCNP, fmt.Errorf("cannot parse CCNP: %v", err)
	}

	derivativeCCNP.Specs, err = createAPIRules(ctx, rules)

	return derivativeCCNP, err
}

func createAPIRules(ctx context.Context, rules api.Rules) (api.Rules, error) {
	specRules := make(api.Rules, len(rules))
	for i, rule := range rules {
		if rule.RequiresDerivative() {
			specRules[i] = denyEgressRule()
		}
	}

	for i, rule := range rules {
		if !rule.RequiresDerivative() {
			specRules[i] = rule
			continue
		}
		newRule, err := rule.CreateDerivative(ctx)
		if err != nil {
			return specRules, err
		}
		specRules[i] = newRule
	}
	return specRules, nil
}

func denyEgressRule() *api.Rule {
	return &api.Rule{
		Egress: []api.EgressRule{},
	}
}

func updateOrCreateCNP(cnp *cilium_v2.CiliumNetworkPolicy) (*cilium_v2.CiliumNetworkPolicy, error) {
	k8sCNP, err := k8s.CiliumClient().CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).
		Get(context.TODO(), cnp.ObjectMeta.Name, v1.GetOptions{})
	if err == nil {
		k8sCNP.ObjectMeta.Labels = cnp.ObjectMeta.Labels
		k8sCNP.Spec = cnp.Spec
		k8sCNP.Specs = cnp.Specs
		k8sCNP.Status = cilium_v2.CiliumNetworkPolicyStatus{}
		return k8s.CiliumClient().CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).Update(context.TODO(), k8sCNP, v1.UpdateOptions{})
	}
	return k8s.CiliumClient().CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).Create(context.TODO(), cnp, v1.CreateOptions{})
}

func updateOrCreateCCNP(ccnp *cilium_v2.CiliumClusterwideNetworkPolicy) (*cilium_v2.CiliumClusterwideNetworkPolicy, error) {
	k8sCCNP, err := k8s.CiliumClient().CiliumV2().CiliumClusterwideNetworkPolicies().
		Get(context.TODO(), ccnp.ObjectMeta.Name, v1.GetOptions{})
	if err == nil {
		k8sCCNP.ObjectMeta.Labels = ccnp.ObjectMeta.Labels
		k8sCCNP.Spec = ccnp.Spec
		k8sCCNP.Specs = ccnp.Specs
		k8sCCNP.Status = cilium_v2.CiliumNetworkPolicyStatus{}

		return k8s.CiliumClient().CiliumV2().CiliumClusterwideNetworkPolicies().Update(context.TODO(), k8sCCNP, v1.UpdateOptions{})
	}

	return k8s.CiliumClient().CiliumV2().CiliumClusterwideNetworkPolicies().
		Create(context.TODO(), ccnp, v1.CreateOptions{})
}

func updateDerivativeStatus(cnp *cilium_v2.CiliumNetworkPolicy, derivativeName string, err error, clusterScoped bool) error {
	status := cilium_v2.CiliumNetworkPolicyNodeStatus{
		LastUpdated: slimv1.Now(),
		Enforcing:   false,
	}

	if err != nil {
		status.OK = false
		status.Error = err.Error()
	} else {
		status.OK = true
	}

	if clusterScoped {
		return updateDerivativeCCNPStatus(cnp, status, derivativeName)
	}

	return updateDerivativeCNPStatus(cnp, status, derivativeName)
}

func updateDerivativeCNPStatus(cnp *cilium_v2.CiliumNetworkPolicy, status cilium_v2.CiliumNetworkPolicyNodeStatus,
	derivativeName string) error {
	// This CNP can be modified by cilium agent or operator. To be able to push
	// the status correctly fetch the last version to avoid updates issues.
	k8sCNP, clientErr := k8s.CiliumClient().CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).
		Get(context.TODO(), cnp.ObjectMeta.Name, v1.GetOptions{})

	if clientErr != nil {
		return fmt.Errorf("cannot get Kubernetes policy: %v", clientErr)
	}

	if k8sCNP.ObjectMeta.UID != cnp.ObjectMeta.UID {
		// This case should not happen, but if the UID does not match make sure
		// that the new policy is not in the cache to not loop over it. The
		// kubernetes watcher should take care about that.
		groupsCNPCache.DeleteCNP(k8sCNP)
		return fmt.Errorf("policy UID mistmatch")
	}

	k8sCNP.SetDerivedPolicyStatus(derivativeName, status)
	groupsCNPCache.UpdateCNP(k8sCNP)

	// TODO: Switch to JSON patch.
	_, err := k8s.CiliumClient().CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).
		UpdateStatus(context.TODO(), k8sCNP, v1.UpdateOptions{})

	return err
}

func updateDerivativeCCNPStatus(cnp *cilium_v2.CiliumNetworkPolicy, status cilium_v2.CiliumNetworkPolicyNodeStatus,
	derivativeName string) error {
	k8sCCNP, clientErr := k8s.CiliumClient().CiliumV2().CiliumClusterwideNetworkPolicies().
		Get(context.TODO(), cnp.ObjectMeta.Name, v1.GetOptions{})

	if clientErr != nil {
		return fmt.Errorf("cannot get Kubernetes policy: %v", clientErr)
	}

	if k8sCCNP.ObjectMeta.UID != cnp.ObjectMeta.UID {
		// This case should not happen, but if the UID does not match make sure
		// that the new policy is not in the cache to not loop over it. The
		// kubernetes watcher should take care of that.
		groupsCNPCache.DeleteCNP(&cilium_v2.CiliumNetworkPolicy{
			ObjectMeta: k8sCCNP.ObjectMeta,
		})
		return fmt.Errorf("policy UID mistmatch")
	}

	k8sCCNP.SetDerivedPolicyStatus(derivativeName, status)
	groupsCNPCache.UpdateCNP(&cilium_v2.CiliumNetworkPolicy{
		TypeMeta:   k8sCCNP.TypeMeta,
		ObjectMeta: k8sCCNP.ObjectMeta,
		Spec:       k8sCCNP.Spec,
		Specs:      k8sCCNP.Specs,
		Status:     k8sCCNP.Status,
	})

	// TODO: Switch to JSON patch
	_, err := k8s.CiliumClient().CiliumV2().CiliumClusterwideNetworkPolicies().
		UpdateStatus(context.TODO(), k8sCCNP, v1.UpdateOptions{})

	return err

}
