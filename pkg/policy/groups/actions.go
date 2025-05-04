// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package groups

import (
	"context"
	"log/slog"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/controller"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

var (
	controllerManager = controller.NewManager()

	addDerivativePolicyControllerGroup    = controller.NewGroup("add-derivative-network-policy")
	updateDerivativePolicyControllerGroup = controller.NewGroup("update-derivative-network-policy")
	deleteDerivativePolicyControllerGroup = controller.NewGroup("delete-derivative-network-policy")
)

// AddDerivativePolicyIfNeeded will create a new CNP if the given CNP has any rules
// that need to create a new derivative policy.
func AddDerivativePolicyIfNeeded(logger *slog.Logger, clientset client.Clientset, clusterName string, cnp *cilium_v2.CiliumNetworkPolicy, clusterScoped bool) {
	if !cnp.RequiresDerivative() {
		logger.Debug(
			"Policy does not have derivative policies, skipped",
			logfields.CiliumNetworkPolicyName, cnp.ObjectMeta.Name,
			logfields.K8sNamespace, cnp.ObjectMeta.Namespace,
		)
		return
	}
	controllerManager.UpdateController(
		"add-derivative-policy-"+cnp.ObjectMeta.Name,
		controller.ControllerParams{
			Group: addDerivativePolicyControllerGroup,
			DoFunc: func(ctx context.Context) error {
				return addDerivativePolicy(ctx, logger, clientset, clusterName, cnp, clusterScoped)
			},
		})
}

// UpdateDerivativePolicyIfNeeded updates or creates a CNP if the given CNP has
// any rule that needs to create a new derivative policy(eg: ToGroups). In case
// that the new CNP does not have any derivative policy and the old one had
// one, it will delete the old policy.
// The function returns true if an update is required for the derivative policy
// and false otherwise.
func UpdateDerivativePolicyIfNeeded(logger *slog.Logger, clientset client.Clientset, clusterName string, newCNP *cilium_v2.CiliumNetworkPolicy, oldCNP *cilium_v2.CiliumNetworkPolicy, clusterScoped bool) bool {
	if !newCNP.RequiresDerivative() && oldCNP.RequiresDerivative() {
		logger.Info(
			"New policy does not have derivative policy, but old had. Deleting old policies",
			logfields.CiliumNetworkPolicyName, newCNP.ObjectMeta.Name,
			logfields.K8sNamespace, newCNP.ObjectMeta.Namespace,
		)

		controllerManager.UpdateController(
			"delete-derivative-policy-"+oldCNP.ObjectMeta.Name,
			controller.ControllerParams{
				Group: deleteDerivativePolicyControllerGroup,
				DoFunc: func(ctx context.Context) error {
					if !clusterScoped {
						if err := clientset.CiliumV2().CiliumNetworkPolicies(oldCNP.ObjectMeta.Namespace).DeleteCollection(
							ctx,
							v1.DeleteOptions{},
							v1.ListOptions{LabelSelector: parentCNP + "=" + string(oldCNP.ObjectMeta.UID)}); err != nil {
							return err
						}
					} else {
						if err := clientset.CiliumV2().CiliumClusterwideNetworkPolicies().DeleteCollection(
							ctx,
							v1.DeleteOptions{},
							v1.ListOptions{LabelSelector: parentCNP + "=" + string(oldCNP.ObjectMeta.UID)}); err != nil {
							return err
						}
					}
					DeleteDerivativeFromCache(oldCNP)
					return nil
				},
			})
		return false
	}

	if !newCNP.RequiresDerivative() {
		return false
	}

	controllerManager.UpdateController(
		"update-derivative-policy-"+newCNP.ObjectMeta.Name,
		controller.ControllerParams{
			Group: updateDerivativePolicyControllerGroup,
			DoFunc: func(ctx context.Context) error {
				return addDerivativePolicy(ctx, logger, clientset, clusterName, newCNP, clusterScoped)
			},
		})
	return true
}

// DeleteDerivativeFromCache deletes the given CNP from the groupsCNPCache to
// no continue pooling new data.
func DeleteDerivativeFromCache(cnp *cilium_v2.CiliumNetworkPolicy) {
	groupsCNPCache.DeleteCNP(cnp)
}

func addDerivativePolicy(ctx context.Context, logger *slog.Logger, clientset client.Clientset, clusterName string, cnp *cilium_v2.CiliumNetworkPolicy, clusterScoped bool) error {
	var (
		scopedLog          *slog.Logger
		derivativePolicy   v1.Object
		derivativeCNP      *cilium_v2.CiliumNetworkPolicy
		derivativeCCNP     *cilium_v2.CiliumClusterwideNetworkPolicy
		derivativeErr, err error
	)
	if clusterScoped {
		scopedLog = logger.With(
			logfields.CiliumClusterwideNetworkPolicyName, cnp.ObjectMeta.Name,
		)
	} else {
		scopedLog = logger.With(
			logfields.CiliumNetworkPolicyName, cnp.ObjectMeta.Name,
			logfields.K8sNamespace, cnp.ObjectMeta.Namespace,
		)
	}

	// If the createDerivativeCNP() fails, a new all block rule will be inserted and
	// the derivative status in the parent policy  will be updated with the
	// error.
	if clusterScoped {
		derivativeCCNP, derivativeErr = createDerivativeCCNP(ctx, logger, clusterName, cnp)
		derivativePolicy = derivativeCCNP
	} else {
		derivativeCNP, derivativeErr = createDerivativeCNP(ctx, logger, clusterName, cnp)
		derivativePolicy = derivativeCNP
	}

	if derivativeErr != nil {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		scopedLog.Error("Cannot create derivative rule. Installing deny-all rule.", logfields.Error, derivativeErr)
		statusErr := updateDerivativeStatus(clientset, cnp, derivativePolicy.GetName(), derivativeErr, clusterScoped)
		if statusErr != nil {
			scopedLog.Error("Cannot update status for derivative policy", logfields.Error, statusErr)
		}
		return derivativeErr
	}

	groupsCNPCache.UpdateCNP(cnp)
	if clusterScoped {
		_, err = updateOrCreateCCNP(clientset, derivativeCCNP)
	} else {
		_, err = updateOrCreateCNP(clientset, derivativeCNP)
	}

	if err != nil {
		statusErr := updateDerivativeStatus(clientset, cnp, derivativePolicy.GetName(), err, clusterScoped)
		if statusErr != nil {
			metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
			scopedLog.Error("Cannot update status for derivative policy", logfields.Error, err)
		}
		return statusErr
	}
	metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()

	err = updateDerivativeStatus(clientset, cnp, derivativePolicy.GetName(), nil, clusterScoped)
	if err != nil {
		scopedLog.Error("Cannot update status for derivative policy", logfields.Error, err)
	}
	return err
}
