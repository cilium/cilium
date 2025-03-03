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

	addDerivativeCNPControllerGroup    = controller.NewGroup("add-derivative-cilium-network-policy")
	updateDerivativeCNPControllerGroup = controller.NewGroup("update-derivative-cilium-network-policy")
	deleteDerivativeCNPControllerGroup = controller.NewGroup("delete-derivative-cilium-network-policy")

	addDerivativeCCNPControllerGroup    = controller.NewGroup("add-derivative-clusterwide-cilium-network-policy")
	updateDerivativeCCNPControllerGroup = controller.NewGroup("update-derivative-clusterwide-cilium-network-policy")
	deleteDerivativeCCNPControllerGroup = controller.NewGroup("delete-derivative-clusterwide-cilium-network-policy")
)

// AddDerivativeCNPIfNeeded will create a new CNP if the given CNP has any rules
// that need to create a new derivative policy.
// It returns a boolean, true in case that all actions are correct, false if
// something fails.
func AddDerivativeCNPIfNeeded(logger *slog.Logger, clientset client.Clientset, cnp *cilium_v2.CiliumNetworkPolicy) bool {
	if !cnp.RequiresDerivative() {
		logger.Debug(
			"CNP does not have derivative policies, skipped",
			logfields.CiliumNetworkPolicyName, cnp.ObjectMeta.Name,
			logfields.K8sNamespace, cnp.ObjectMeta.Namespace,
		)
		return true
	}
	controllerManager.UpdateController(
		"add-derivative-cnp-"+cnp.ObjectMeta.Name,
		controller.ControllerParams{
			Group: addDerivativeCNPControllerGroup,
			DoFunc: func(ctx context.Context) error {
				return addDerivativePolicy(ctx, logger, clientset, cnp, false)
			},
		})
	return true
}

// AddDerivativeCCNPIfNeeded will create a new CCNP if the given NetworkPolicy has any rules
// that need to create a new derivative policy.
// It returns a boolean, true in case that all actions are correct, false if
// something fails.
func AddDerivativeCCNPIfNeeded(logger *slog.Logger, clientset client.Clientset, cnp *cilium_v2.CiliumNetworkPolicy) bool {
	if !cnp.RequiresDerivative() {
		logger.Debug(
			"CCNP does not have derivative policies, skipped",
			logfields.CiliumClusterwideNetworkPolicyName, cnp.ObjectMeta.Name,
		)
		return true
	}
	controllerManager.UpdateController(
		"add-derivative-ccnp-"+cnp.ObjectMeta.Name,
		controller.ControllerParams{
			Group: addDerivativeCCNPControllerGroup,
			DoFunc: func(ctx context.Context) error {
				return addDerivativePolicy(ctx, logger, clientset, cnp, true)
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
func UpdateDerivativeCNPIfNeeded(logger *slog.Logger, clientset client.Clientset, newCNP *cilium_v2.CiliumNetworkPolicy, oldCNP *cilium_v2.CiliumNetworkPolicy) bool {
	if !newCNP.RequiresDerivative() && oldCNP.RequiresDerivative() {
		logger.Info(
			"New CNP does not have derivative policy, but old had. Deleting old policies",
			logfields.CiliumNetworkPolicyName, newCNP.ObjectMeta.Name,
			logfields.K8sNamespace, newCNP.ObjectMeta.Namespace,
		)

		controllerManager.UpdateController(
			"delete-derivative-cnp-"+oldCNP.ObjectMeta.Name,
			controller.ControllerParams{
				Group: deleteDerivativeCNPControllerGroup,
				DoFunc: func(ctx context.Context) error {
					return DeleteDerivativeCNP(ctx, logger, clientset, oldCNP)
				},
			})
		return false
	}

	if !newCNP.RequiresDerivative() {
		return false
	}

	controllerManager.UpdateController(
		"update-derivative-cnp-"+newCNP.ObjectMeta.Name,
		controller.ControllerParams{
			Group: updateDerivativeCNPControllerGroup,
			DoFunc: func(ctx context.Context) error {
				return addDerivativePolicy(ctx, logger, clientset, newCNP, false)
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
func UpdateDerivativeCCNPIfNeeded(logger *slog.Logger, clientset client.Clientset, newCCNP *cilium_v2.CiliumNetworkPolicy, oldCCNP *cilium_v2.CiliumNetworkPolicy) bool {
	if !newCCNP.RequiresDerivative() && oldCCNP.RequiresDerivative() {
		logger.Info(
			"New CCNP does not have derivative policy, but old had. Deleting old policies",
			logfields.CiliumClusterwideNetworkPolicyName, newCCNP.ObjectMeta.Name,
		)

		controllerManager.UpdateController(
			"delete-derivative-ccnp-"+oldCCNP.ObjectMeta.Name,
			controller.ControllerParams{
				Group: deleteDerivativeCCNPControllerGroup,
				DoFunc: func(ctx context.Context) error {
					return DeleteDerivativeCCNP(ctx, logger, clientset, oldCCNP)
				},
			})
		return false
	}

	if !newCCNP.RequiresDerivative() {
		return false
	}

	controllerManager.UpdateController(
		"update-derivative-ccnp-"+newCCNP.ObjectMeta.Name,
		controller.ControllerParams{
			Group: updateDerivativeCCNPControllerGroup,
			DoFunc: func(ctx context.Context) error {
				return addDerivativePolicy(ctx, logger, clientset, newCCNP, true)
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
func DeleteDerivativeCNP(ctx context.Context, logger *slog.Logger, clientset client.Clientset, cnp *cilium_v2.CiliumNetworkPolicy) error {
	if !cnp.RequiresDerivative() {
		logger.Debug(
			"CNP does not have derivative policies, skipped",
			logfields.CiliumNetworkPolicyName, cnp.ObjectMeta.Name,
			logfields.K8sNamespace, cnp.ObjectMeta.Namespace,
		)
		return nil
	}

	err := clientset.CiliumV2().CiliumNetworkPolicies(cnp.ObjectMeta.Namespace).DeleteCollection(
		ctx,
		v1.DeleteOptions{},
		v1.ListOptions{LabelSelector: parentCNP + "=" + string(cnp.ObjectMeta.UID)})

	if err != nil {
		return err
	}

	DeleteDerivativeFromCache(cnp)
	return nil
}

// DeleteDerivativeCCNP if the given policy has a derivative constraint, the
// given CCNP will be deleted from store and the cache.
func DeleteDerivativeCCNP(ctx context.Context, logger *slog.Logger, clientset client.Clientset, ccnp *cilium_v2.CiliumNetworkPolicy) error {
	if !ccnp.RequiresDerivative() {
		logger.Debug(
			"CCNP does not have derivative policies, skipped",
			logfields.CiliumClusterwideNetworkPolicyName, ccnp.ObjectMeta.Name,
		)
		return nil
	}

	err := clientset.CiliumV2().CiliumClusterwideNetworkPolicies().DeleteCollection(
		ctx,
		v1.DeleteOptions{},
		v1.ListOptions{LabelSelector: parentCNP + "=" + string(ccnp.ObjectMeta.UID)})
	if err != nil {
		return err
	}

	DeleteDerivativeFromCache(ccnp)
	return nil
}

func addDerivativePolicy(ctx context.Context, logger *slog.Logger, clientset client.Clientset, cnp *cilium_v2.CiliumNetworkPolicy, clusterScoped bool) error {
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
		derivativeCCNP, derivativeErr = createDerivativeCCNP(ctx, cnp)
		derivativePolicy = derivativeCCNP
	} else {
		derivativeCNP, derivativeErr = createDerivativeCNP(ctx, cnp)
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
