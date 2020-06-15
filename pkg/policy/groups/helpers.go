// Copyright 2018-2020 Authors of Cilium
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

package groups

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/policy/api"

	"k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	cnpKindName = "derivative"
	parentCNP   = "io.cilium.network.policy.parent.uuid"
	cnpKindKey  = "io.cilium.network.policy.kind"
)

var (
	blockOwnerDeletionPtr = true
)

func getDerivativeName(cnp *cilium_v2.CiliumNetworkPolicy) string {
	return fmt.Sprintf(
		"%s-togroups-%s",
		cnp.GetObjectMeta().GetName(),
		cnp.GetObjectMeta().GetUID())
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
				APIVersion:         cilium_v2.SchemeGroupVersion.String(),
				Kind:               cilium_v2.CNPKindDefinition,
				Name:               cnp.ObjectMeta.Name,
				UID:                cnp.ObjectMeta.UID,
				BlockOwnerDeletion: &blockOwnerDeletionPtr,
			}},
			Labels: map[string]string{
				parentCNP:  string(cnp.ObjectMeta.UID),
				cnpKindKey: cnpKindName,
			},
		},
	}

	rules, err := cnp.Parse()
	if err != nil {
		return nil, fmt.Errorf("Cannot parse policies: %s", err)
	}

	derivativeCNP.Specs = make(api.Rules, len(rules))
	for i, rule := range rules {
		if rule.RequiresDerivative() {
			derivativeCNP.Specs[i] = denyEgressRule()
		}
	}

	for i, rule := range rules {
		if !rule.RequiresDerivative() {
			derivativeCNP.Specs[i] = rule
			continue
		}
		newRule, err := rule.CreateDerivative(ctx)
		if err != nil {
			return derivativeCNP, err
		}
		derivativeCNP.Specs[i] = newRule
	}
	return derivativeCNP, nil
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

func updateDerivativeStatus(cnp *cilium_v2.CiliumNetworkPolicy, derivativeName string, err error) error {
	status := cilium_v2.CiliumNetworkPolicyNodeStatus{
		LastUpdated: cilium_v2.NewTimestamp(),
		Enforcing:   false,
	}

	if err != nil {
		status.OK = false
		status.Error = err.Error()
	} else {
		status.OK = true
	}

	// This CNP can be modified by cilium agent or operator. To be able to push
	// the status correctly fetch the last version to avoid updates issues.
	k8sCNPStatus, clientErr := k8s.CiliumClient().CiliumV2().
		CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).
		Get(context.TODO(), cnp.ObjectMeta.Name, v1.GetOptions{})
	if clientErr != nil {
		return fmt.Errorf("Cannot get Kubernetes policy: %s", clientErr)
	}
	if k8sCNPStatus.ObjectMeta.UID != cnp.ObjectMeta.UID {
		// This case should not happen, but if the UID does not match make sure
		// that the new policy is not in the cache to not loop over it. The
		// kubernetes watcher should take care about that.
		groupsCNPCache.DeleteCNP(k8sCNPStatus)
		return fmt.Errorf("Policy UID mistmatch")
	}
	k8sCNPStatus.SetDerivedPolicyStatus(derivativeName, status)
	groupsCNPCache.UpdateCNP(k8sCNPStatus)
	// TODO: switch to JSON Patch
	_, err = k8s.CiliumClient().CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).UpdateStatus(context.TODO(), cnp, v1.UpdateOptions{})
	return err
}
