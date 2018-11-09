// Copyright 2017-2018 Authors of Cilium
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
	"time"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	MaxNumberOfAttempts = 5
	SleepDuration       = 5 * time.Second
)

// AddDerivativerenCNPIfNeeded will create a new CNP if the given CNP has any rule
// that need to create a new derivative policy.
func AddDerivativerenCNPIfNeeded(cnp *cilium_v2.CiliumNetworkPolicy) bool {
	if !cnp.HasDerivatives() {
		log.WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
			logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
		}).Debug("CNP does not have derivative policies, skipped")
		return true
	}
	return addDerivativeCNP(cnp)
}

// UpdateDerivativeCNPIfNeeded will update or create a  CNP if the given CNP has
// any rule that need to create a new derivative policy.  In case that the newCNP
// will not have any derivative policy and the old one had one, it'll delete the
// old policy.
func UpdateDerivativeCNPIfNeeded(newCNP *cilium_v2.CiliumNetworkPolicy, oldCNP *cilium_v2.CiliumNetworkPolicy) bool {
	if !newCNP.HasDerivatives() && oldCNP.HasDerivatives() {
		log.WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicyName: newCNP.ObjectMeta.Name,
			logfields.K8sNamespace:            newCNP.ObjectMeta.Namespace,
		}).Info("New CNP does not have derivative policy, but old had. Deleted old policies")
		DeleteDerivativeCNP(oldCNP)
		return false
	}

	if !newCNP.HasDerivatives() {
		return false
	}
	return addDerivativeCNP(newCNP)
}

// DeleteDerivativeCNP if the given policy has any derivatives policy will be
// deleted from the repo and the cache.
func DeleteDerivativeCNP(cnp *cilium_v2.CiliumNetworkPolicy) error {

	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
		logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
	})

	if !cnp.HasDerivatives() {
		scopedLog.Debug("CNP does not have derivatives policies, skipped")
		return nil
	}

	k8sClient, err := getK8sClient()
	if err != nil {
		scopedLog.WithError(err).Error("Cannot get kubertenes configuration")
	}

	err = k8sClient.CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).DeleteCollection(
		&v1.DeleteOptions{},
		v1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", parentCNP, cnp.ObjectMeta.UID)})

	ToGroupsCNPCache.DeleteCNP(cnp)
	return err
}

func addDerivativeCNP(cnp *cilium_v2.CiliumNetworkPolicy) bool {

	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
		logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
	})

	var derivativeCNP *cilium_v2.CiliumNetworkPolicy
	var err error
	for numAttempts := 0; numAttempts <= MaxNumberOfAttempts; numAttempts++ {
		derivativeCNP, err = getDerivativeCNP(cnp)
		if err == nil {
			break
		}
		scopedLog.WithError(err).Error("Cannot create derivative")
		statusErr := updateDerivativeStatus(cnp, derivativeCNP.ObjectMeta.Name, err)
		if statusErr != nil {
			log.WithError(err).Error("Cannot update CNP status on invalid derivative")
		}
		if numAttempts == MaxNumberOfAttempts {
			return false
		}
		time.Sleep(SleepDuration)
	}
	ToGroupsCNPCache.UpdateCNP(cnp)
	_, err = updateOrCreateCNP(derivativeCNP)
	if err != nil {
		statusErr := updateDerivativeStatus(cnp, derivativeCNP.ObjectMeta.Name, err)
		if statusErr != nil {
			scopedLog.WithError(err).Error("Cannot update CNP status on invalid derivative")
		}
		return false
	}

	err = updateDerivativeStatus(cnp, derivativeCNP.ObjectMeta.Name, nil)
	if err != nil {
		scopedLog.WithError(err).Error("Cannot update CNP status on valid derivative policy")
		return false
	}

	return true
}
