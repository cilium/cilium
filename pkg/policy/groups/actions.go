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
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// maxNumberOfAttempts Number of times that try to retrieve a information from a cloud provider.
	maxNumberOfAttempts = 5
	// SleepDuration time that sleep in case that can't retrieve information from a cloud provider.
	sleepDuration = 5 * time.Second
)

var (
	controllerManager = controller.NewManager()
)

// AddDerivativeCNPIfNeeded will create a new CNP if the given CNP has any rules
// that need to create a new derivative policy.
// It returns a boolean, true in case that all actions are correct, false if
// something fails.
func AddDerivativeCNPIfNeeded(cnp *cilium_v2.CiliumNetworkPolicy) bool {
	if !cnp.RequiresDerivative() {
		log.WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
			logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
		}).Debug("CNP does not have derivative policies, skipped")
		return true
	}
	controllerManager.UpdateController(fmt.Sprintf("add-derivative-cnp-%s", cnp.ObjectMeta.Name),
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				return addDerivativePolicy(ctx, cnp, false)
			},
		})
	return true
}

// AddDerivativeCCNPIfNeeded will create a new CCNP if the given NetworkPolicy has any rules
// that need to create a new derivative policy.
// It returns a boolean, true in case that all actions are correct, false if
// something fails.
func AddDerivativeCCNPIfNeeded(cnp *cilium_v2.CiliumNetworkPolicy) bool {
	if !cnp.RequiresDerivative() {
		log.WithFields(logrus.Fields{
			logfields.CiliumClusterwideNetworkPolicyName: cnp.ObjectMeta.Name,
		}).Debug("CCNP does not have derivative policies, skipped")
		return true
	}
	controllerManager.UpdateController(fmt.Sprintf("add-derivative-ccnp-%s", cnp.ObjectMeta.Name),
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				return addDerivativePolicy(ctx, cnp, true)
			},
		})
	return true
}

// UpdateDerivativeCNPIfNeeded updates or creates a CNP if the given CNP has
// any rule that needs to create a new derivative policy(eg: ToGroups). In case
// that the new CNP does not have any derivative policy and the old one had
// one, it will delete the old policy.
// The function returns true if an update is required for the derivative policy
// and false otherwise.
func UpdateDerivativeCNPIfNeeded(newCNP *cilium_v2.CiliumNetworkPolicy, oldCNP *cilium_v2.CiliumNetworkPolicy) bool {
	if !newCNP.RequiresDerivative() && oldCNP.RequiresDerivative() {
		log.WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicyName: newCNP.ObjectMeta.Name,
			logfields.K8sNamespace:            newCNP.ObjectMeta.Namespace,
		}).Info("New CNP does not have derivative policy, but old had. Deleting old policies")

		controllerManager.UpdateController(fmt.Sprintf("delete-derivative-cnp-%s", oldCNP.ObjectMeta.Name),
			controller.ControllerParams{
				DoFunc: func(ctx context.Context) error {
					return DeleteDerivativeCNP(oldCNP)
				},
			})
		return false
	}

	if !newCNP.RequiresDerivative() {
		return false
	}

	controllerManager.UpdateController(fmt.Sprintf("update-derivative-cnp-%s", newCNP.ObjectMeta.Name),
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				return addDerivativePolicy(ctx, newCNP, false)
			},
		})
	return true
}

// UpdateDerivativeCCNPIfNeeded updates or creates a CCNP if the given CCNP has
// any rule that needs to create a new derivative policy(eg: ToGroups). In case
// that the new CCNP does not have any derivative policy and the old one had
// one, it will delete the old policy.
// The function returns true if an update is required for the derivative policy
// and false otherwise.
func UpdateDerivativeCCNPIfNeeded(newCCNP *cilium_v2.CiliumNetworkPolicy, oldCCNP *cilium_v2.CiliumNetworkPolicy) bool {
	if !newCCNP.RequiresDerivative() && oldCCNP.RequiresDerivative() {
		log.WithFields(logrus.Fields{
			logfields.CiliumClusterwideNetworkPolicyName: newCCNP.ObjectMeta.Name,
		}).Info("New CCNP does not have derivative policy, but old had. Deleting old policies")

		controllerManager.UpdateController(fmt.Sprintf("delete-derivative-ccnp-%s", oldCCNP.ObjectMeta.Name),
			controller.ControllerParams{
				DoFunc: func(ctx context.Context) error {
					return DeleteDerivativeCCNP(oldCCNP)
				},
			})
		return false
	}

	if !newCCNP.RequiresDerivative() {
		return false
	}

	controllerManager.UpdateController(fmt.Sprintf("update-derivative-ccnp-%s", newCCNP.ObjectMeta.Name),
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				return addDerivativePolicy(ctx, newCCNP, true)
			},
		})
	return true
}

// DeleteDerivativeFromCache deletes the given CNP from the groupsCNPCache to
// no continue pooling new data.
func DeleteDerivativeFromCache(cnp *cilium_v2.CiliumNetworkPolicy) {
	groupsCNPCache.DeleteCNP(cnp)
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

	err := k8s.CiliumClient().CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).DeleteCollection(
		context.TODO(),
		v1.DeleteOptions{},
		v1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", parentCNP, cnp.ObjectMeta.UID)})

	if err != nil {
		return err
	}

	DeleteDerivativeFromCache(cnp)
	return nil
}

// DeleteDerivativeCCNP if the given policy has a derivative constraint, the
// given CCNP will be deleted from store and the cache.
func DeleteDerivativeCCNP(ccnp *cilium_v2.CiliumNetworkPolicy) error {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.CiliumClusterwideNetworkPolicyName: ccnp.ObjectMeta.Name,
	})

	if !ccnp.RequiresDerivative() {
		scopedLog.Debug("CCNP does not have derivative policies, skipped")
		return nil
	}

	err := k8s.CiliumClient().CiliumV2().CiliumClusterwideNetworkPolicies().DeleteCollection(
		context.TODO(),
		v1.DeleteOptions{},
		v1.ListOptions{LabelSelector: fmt.Sprintf("%s=%s", parentCNP, ccnp.ObjectMeta.UID)})
	if err != nil {
		return err
	}

	DeleteDerivativeFromCache(ccnp)
	return nil
}

func addDerivativePolicy(ctx context.Context, cnp *cilium_v2.CiliumNetworkPolicy, clusterScoped bool) error {
	var (
		scopedLog          *logrus.Entry
		derivativePolicy   v1.Object
		derivativeCNP      *cilium_v2.CiliumNetworkPolicy
		derivativeCCNP     *cilium_v2.CiliumClusterwideNetworkPolicy
		derivativeErr, err error
	)
	if clusterScoped {
		scopedLog = log.WithFields(logrus.Fields{
			logfields.CiliumClusterwideNetworkPolicyName: cnp.ObjectMeta.Name,
		})
	} else {
		scopedLog = log.WithFields(logrus.Fields{
			logfields.CiliumNetworkPolicyName: cnp.ObjectMeta.Name,
			logfields.K8sNamespace:            cnp.ObjectMeta.Namespace,
		})
	}

	// The maxNumberOfAttempts is to not hit the limits of cloud providers API.
	// Also, the derivativeErr is never returned, if not the controller will
	// hit this function and the cloud providers limit will be raised. This
	// will cause a disaster, due all other policies will hit the limit as
	// well.
	// If the createDerivativeCNP() fails, a new all block rule will be inserted and
	// the derivative status in the parent policy  will be updated with the
	// error.
	for numAttempts := 0; numAttempts <= maxNumberOfAttempts; numAttempts++ {
		if clusterScoped {
			derivativeCCNP, derivativeErr = createDerivativeCCNP(ctx, cnp)
			derivativePolicy = derivativeCCNP
		} else {
			derivativeCNP, derivativeErr = createDerivativeCNP(ctx, cnp)
			derivativePolicy = derivativeCNP
		}

		if derivativeErr == nil {
			break
		}
		metrics.PolicyImportErrorsTotal.Inc()
		scopedLog.WithError(derivativeErr).Error("Cannot create derivative rule. Installing deny-all rule.")
		statusErr := updateDerivativeStatus(cnp, derivativePolicy.GetName(), derivativeErr, clusterScoped)
		if statusErr != nil {
			scopedLog.WithError(statusErr).Error("Cannot update status for derivative policy")
		}
		time.Sleep(sleepDuration)
	}

	groupsCNPCache.UpdateCNP(cnp)
	if clusterScoped {
		_, err = updateOrCreateCCNP(derivativeCCNP)
	} else {
		_, err = updateOrCreateCNP(derivativeCNP)
	}

	if err != nil {
		statusErr := updateDerivativeStatus(cnp, derivativePolicy.GetName(), err, clusterScoped)
		if statusErr != nil {
			metrics.PolicyImportErrorsTotal.Inc()
			scopedLog.WithError(err).Error("Cannot update status for derivative policy")
		}
		return statusErr
	}

	err = updateDerivativeStatus(cnp, derivativePolicy.GetName(), nil, clusterScoped)
	if err != nil {
		scopedLog.WithError(err).Error("Cannot update status for derivative policy")
	}
	return err
}
