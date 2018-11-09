// Copyright 2018 Authors of Cilium
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
	"fmt"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/policy/api"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	parentCNP   = "parentCNP"
	cnpKindKey  = "CNPKind"
	cnpKindName = "derivative"
)

var (
	globalK8sClient       *clientset.Clientset
	k8sMutex              = lock.Mutex{}
	blockOwnerDeletionPtr = true
)

// createDerivativeCNP will return a new CNP based on the given rule.
func createDerivativeCNP(cnp *cilium_v2.CiliumNetworkPolicy) (*cilium_v2.CiliumNetworkPolicy, error) {
	derivativeCNP := cnp.DeepCopy()

	// CNP informer may provide a CNP object without APIVersion or Kind.
	// Setting manually to make sure that the derivative policy works ok.
	derivativeCNP.ObjectMeta.OwnerReferences = []v1.OwnerReference{{
		APIVersion:         cilium_v2.SchemeGroupVersion.String(),
		Kind:               cilium_v2.CNPKindDefinition,
		Name:               cnp.ObjectMeta.Name,
		UID:                cnp.ObjectMeta.UID,
		BlockOwnerDeletion: &blockOwnerDeletionPtr}}
	derivativeCNP.ObjectMeta.Name = fmt.Sprintf(
		"%s-togroups-%s",
		derivativeCNP.ObjectMeta.Name,
		cnp.ObjectMeta.UID)
	derivativeCNP.ObjectMeta.UID = ""
	derivativeCNP.ObjectMeta.ResourceVersion = ""
	derivativeCNP.ObjectMeta.Labels = map[string]string{
		parentCNP:  string(cnp.ObjectMeta.UID),
		cnpKindKey: cnpKindName,
	}
	derivativeCNP.Spec = &api.Rule{}
	derivativeCNP.Specs = api.Rules{}

	rules, err := cnp.Parse()
	if err != nil {
		return nil, fmt.Errorf("Cannot parse policies: %s", err)
	}

	for _, rule := range rules {
		if !rule.RequiresDerivative() {
			continue
		}
		newRule, err := rule.CreateDerivative()
		if err != nil {
			return derivativeCNP, err
		}
		derivativeCNP.Specs = append(derivativeCNP.Specs, newRule)
	}

	return derivativeCNP, nil
}

// getK8sClient return the kubernetes apiserver connection
func getK8sClient() (*clientset.Clientset, error) {
	k8sMutex.Lock()
	defer k8sMutex.Unlock()
	if globalK8sClient != nil {
		return globalK8sClient, nil
	}

	restConfig, err := k8s.CreateConfig()
	if err != nil {
		return nil, fmt.Errorf("Unable to create rest configuration: %s", err)
	}
	k8sClient, err := clientset.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("Unable to create Kubernetes configuration: %s", err)

	}
	globalK8sClient = k8sClient
	return globalK8sClient, nil
}

func updateCNPStatus(cnp *cilium_v2.CiliumNetworkPolicy) (*cilium_v2.CiliumNetworkPolicy, error) {
	k8sClient, err := getK8sClient()
	if err != nil {
		// @TODO change the error here
		return nil, err
	}
	return k8sClient.CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).UpdateStatus(cnp)
}

func updateOrCreateCNP(cnp *cilium_v2.CiliumNetworkPolicy) (*cilium_v2.CiliumNetworkPolicy, error) {
	k8sClient, err := getK8sClient()
	if err != nil {
		return nil, err
	}
	k8sCNP, err := k8sClient.CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).
		Get(cnp.ObjectMeta.Name, v1.GetOptions{})
	if err == nil {
		k8sCNP.ObjectMeta.Labels = cnp.ObjectMeta.Labels
		k8sCNP.Spec = cnp.Spec
		k8sCNP.Specs = cnp.Specs
		k8sCNP.Status = cilium_v2.CiliumNetworkPolicyStatus{}
		return k8sClient.CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).Update(k8sCNP)
	}
	return k8sClient.CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).Create(cnp)
}

func updateDerivativeStatus(cnp *cilium_v2.CiliumNetworkPolicy, derivativeName string, err error) error {
	status := cilium_v2.CiliumNetworkPolicyNodeStatus{
		LastUpdated: cilium_v2.NewTimestamp(),
		Enforcing:   false,
	}

	if err != nil {
		status.OK = false
		status.Error = fmt.Sprintf("%v", err.Error())
	} else {
		status.OK = true
		status.Error = ""
	}

	k8sClient, clientErr := getK8sClient()
	if clientErr != nil {
		return fmt.Errorf("Cannot get Kubernetes apiserver client: %s", clientErr)
	}
	// This CNP can be modified by cilium agent or operator. To be able to push
	// the status correctly fetch the last version to avoid updates issues.
	k8sCNPStatus, clientErr := k8sClient.CiliumV2().
		CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).
		Get(cnp.ObjectMeta.Name, v1.GetOptions{})
	if clientErr != nil {
		return fmt.Errorf("Cannot get Kubernetes policy: %s", clientErr)
	}
	if k8sCNPStatus.ObjectMeta.UID != cnp.ObjectMeta.UID {
		groupsCNPCache.DeleteCNP(k8sCNPStatus)
		return fmt.Errorf("Policy UID mistmatch")
	}
	k8sCNPStatus.SetDerivedPolicyStatus(derivativeName, status)
	groupsCNPCache.UpdateCNP(k8sCNPStatus)
	_, err = updateCNPStatus(k8sCNPStatus)
	return err
}
