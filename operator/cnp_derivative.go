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

package main

import (
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/api"
	_ "github.com/cilium/cilium/pkg/policy/groups"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	cnpKindName = "derivative"
	parentCNP   = "io.cilium.network.policy.parent.uuid"
	cnpKindKey  = "io.cilium.network.policy.kind"

	// maxNumberOfAttempts Number of times that try to retrieve a information from a cloud provider.
	maxNumberOfAttempts = 5
	// SleepDuration time that sleep in case that can't retrieve information from a cloud provider.
	sleepDuration = 5 * time.Second
)

var (
	controllerManager     = controller.NewManager()
	globalK8sClient       *clientset.Clientset
	k8sMutex              = lock.Mutex{}
	blockOwnerDeletionPtr = true
)

func getDerivativeName(cnp *cilium_v2.CiliumNetworkPolicy) string {
	return fmt.Sprintf(
		"%s-togroups-%s",
		cnp.GetObjectMeta().GetName(),
		cnp.GetObjectMeta().GetUID())
}

// createDerivativeCNP will return a new CNP based on the given rule.
func createDerivativeCNP(cnp *cilium_v2.CiliumNetworkPolicy) (*cilium_v2.CiliumNetworkPolicy, error) {
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
		newRule, err := rule.CreateDerivative()
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

func updateCNPStatus(cnp *cilium_v2.CiliumNetworkPolicy) (*cilium_v2.CiliumNetworkPolicy, error) {
	return ciliumNPClient.CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).UpdateStatus(cnp)
}

func updateOrCreateCNP(cnp *cilium_v2.CiliumNetworkPolicy) (*cilium_v2.CiliumNetworkPolicy, error) {
	k8sCNP, err := ciliumNPClient.CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).
		Get(cnp.ObjectMeta.Name, v1.GetOptions{})
	if err == nil {
		k8sCNP.ObjectMeta.Labels = cnp.ObjectMeta.Labels
		k8sCNP.Spec = cnp.Spec
		k8sCNP.Specs = cnp.Specs
		k8sCNP.Status = cilium_v2.CiliumNetworkPolicyStatus{}
		return ciliumNPClient.CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).Update(k8sCNP)
	}
	return ciliumNPClient.CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).Create(cnp)
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
	k8sCNPStatus, clientErr := ciliumNPClient.CiliumV2().
		CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).
		Get(cnp.ObjectMeta.Name, v1.GetOptions{})
	if clientErr != nil {
		return fmt.Errorf("Cannot get Kubernetes policy: %s", clientErr)
	}
	if k8sCNPStatus.ObjectMeta.UID != cnp.ObjectMeta.UID {
		// This case should not happen, but if the UID does not match make sure
		// that the new policy is not in the cache to not loop over it. The
		// kubernetes watcher should take care about that.
		cnpCache.DeleteCNP(k8sCNPStatus)
		return fmt.Errorf("Policy UID mistmatch")
	}
	k8sCNPStatus.SetDerivedPolicyStatus(derivativeName, status)
	cnpCache.UpdateCNP(k8sCNPStatus)
	_, err = updateCNPStatus(k8sCNPStatus)
	return err
}

// DeleteDerivativeFromCache deletes the given CNP from the cnpCache to
// no continue pooling new data.
func DeleteDerivativeFromCache(cnp *cilium_v2.CiliumNetworkPolicy) {
	cnpCache.DeleteCNP(cnp)
}

// DeleteDerivativeCNP if the given policy has a derivative constraint,the
// given CNP will be deleted from store and the cache.
func DeleteDerivativeCNP(cnp *cilium_v2.CiliumNetworkPolicy) error {

	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
		logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
	})

	if !cnp.RequiresDerivative() {
		scopedLog.Debug("CNP does not have derivative policies, skipped")
		return nil
	}

	err := ciliumNPClient.CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).DeleteCollection(
		&v1.DeleteOptions{},
		v1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", parentCNP, cnp.ObjectMeta.UID)})
	if err != nil {
		return err
	}

	DeleteDerivativeFromCache(cnp)
	return nil
}

func addDerivativeCNP(cnp *cilium_v2.CiliumNetworkPolicy) error {

	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
		logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
	})

	var derivativeCNP *cilium_v2.CiliumNetworkPolicy
	var derivativeErr error

	// The maxNumberOfAttempts is to not hit the limits of cloud providers API.
	// Also, the derivativeErr is never returned, if not the controller will
	// hit this function and the cloud providers limit will be raised. This
	// will cause a disaster, due all other policies will hit the limit as
	// well.
	// If the createDerivativeCNP() fails, a new all block rule will be inserted and
	// the derivative status in the parent policy  will be updated with the
	// error.
	for numAttempts := 0; numAttempts <= maxNumberOfAttempts; numAttempts++ {
		derivativeCNP, derivativeErr = createDerivativeCNP(cnp)
		if derivativeErr == nil {
			break
		}
		scopedLog.WithError(derivativeErr).Error("Cannot create derivative rule. Installing deny-all rule.")
		statusErr := updateDerivativeStatus(cnp, derivativeCNP.ObjectMeta.Name, derivativeErr)
		if statusErr != nil {
			scopedLog.WithError(statusErr).Error("Cannot update CNP status for derivative policy")
		}
		time.Sleep(sleepDuration)
	}
	cnpCache.UpdateCNP(cnp)
	_, err := updateOrCreateCNP(derivativeCNP)
	if err != nil {
		statusErr := updateDerivativeStatus(cnp, derivativeCNP.ObjectMeta.Name, err)
		if statusErr != nil {
			scopedLog.WithError(err).Error("Cannot update CNP status for derivative policy")
		}
		return statusErr
	}

	err = updateDerivativeStatus(cnp, derivativeCNP.ObjectMeta.Name, nil)
	if err != nil {
		scopedLog.WithError(err).Error("Cannot update CNP status for derivative policy")
	}
	return err
}
