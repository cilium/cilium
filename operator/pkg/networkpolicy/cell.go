// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// The networkpolicy package performs basic policy validation and updates
// the policy's Status field as relevant.

package networkpolicy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	cilium_api_v2_apply "github.com/cilium/cilium/pkg/k8s/client/applyconfiguration/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"network-policy-validator",
	"Validates CNPs and CCNPs and reports their validity status",

	cell.Config(defaultConfig),
	cell.Invoke(registerPolicyValidator),
)

type Config struct {
	ValidateNetworkPolicy bool `mapstructure:"validate-network-policy"`
}

var defaultConfig = Config{
	ValidateNetworkPolicy: true,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("validate-network-policy", def.ValidateNetworkPolicy, "Whether to enable or disable the informational network policy validator")
}

type PolicyParams struct {
	cell.In

	Logger       *slog.Logger
	JobGroup     job.Group
	Clientset    k8s_client.Clientset
	DaemonConfig *option.DaemonConfig

	Cfg Config

	CNPResource  resource.Resource[*cilium_api_v2.CiliumNetworkPolicy]
	CCNPResource resource.Resource[*cilium_api_v2.CiliumClusterwideNetworkPolicy]
}

// The policyValidator validates network policy and reports the results in to the
// policy's Status field. It validates both CiliumNetworkPolicy and CilumClusterwideNetworkPolicy
type policyValidator struct {
	params *PolicyParams
}

func registerPolicyValidator(params PolicyParams) {
	if !params.Cfg.ValidateNetworkPolicy {
		params.Logger.Debug("CNP / CCNP validator disabled")
		return
	}

	if !option.Config.EnableCiliumNetworkPolicy && !option.Config.EnableCiliumClusterwideNetworkPolicy {
		params.Logger.Info(fmt.Sprintf("CNP / CCNP validator doesn't run when CNP and CCNP are disabled (%s=false AND %s=false)", option.EnableCiliumNetworkPolicy, option.EnableCiliumClusterwideNetworkPolicy))
		return
	}

	pv := &policyValidator{
		params: &params,
	}

	params.Logger.Info("Registering CNP / CCNP validator")
	params.JobGroup.Add(job.Observer(
		"cnp-validation",
		pv.handleCNPEvent,
		params.CNPResource,
	))
	params.JobGroup.Add(job.Observer(
		"ccnp-validation",
		pv.handleCCNPEvent,
		params.CCNPResource,
	))
}

func (pv *policyValidator) handleCNPEvent(ctx context.Context, event resource.Event[*cilium_api_v2.CiliumNetworkPolicy]) error {
	var err error
	defer func() {
		event.Done(err)
	}()
	if event.Kind != resource.Upsert {
		return nil
	}

	pol := event.Object
	log := pv.params.Logger.With(
		logfields.K8sNamespace, pol.Namespace,
		logfields.CiliumNetworkPolicyName, pol.Name,
	)

	// need to clone anyways, because Sanitize is mutating
	newPol := pol.DeepCopy()

	var errs error
	if newPol.Spec != nil {
		errs = errors.Join(errs, newPol.Spec.Sanitize())
	}
	for _, r := range newPol.Specs {
		errs = errors.Join(errs, r.Sanitize())
	}

	update := updateCondition(event.Object.Status.Conditions, errs)
	if update == nil {
		return nil
	}

	if errs != nil {
		log.ErrorContext(ctx, "Detected invalid CNP, setting condition", logfields.Error, errs)
	} else {
		log.DebugContext(ctx, "CNP now valid, setting condition")
	}

	// Using the PatchStatus subresource will prevent the generation from being bumped.
	_, err = pv.params.Clientset.CiliumV2().CiliumNetworkPolicies(pol.Namespace).ApplyStatus(
		ctx,
		cilium_api_v2_apply.CiliumNetworkPolicy(pol.Name, pol.Namespace).WithStatus(
			cilium_api_v2_apply.CiliumNetworkPolicyStatus().WithConditions(update),
		).WithResourceVersion(pol.ResourceVersion),
		metav1.ApplyOptions{FieldManager: "cilium-operator"},
	)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		log.ErrorContext(ctx, "failed to update CNP status", logfields.Error, err)
	}

	return err
}

func (pv *policyValidator) handleCCNPEvent(ctx context.Context, event resource.Event[*cilium_api_v2.CiliumClusterwideNetworkPolicy]) error {
	var err error
	defer func() {
		event.Done(err)
	}()
	if event.Kind != resource.Upsert {
		return nil
	}

	pol := event.Object
	log := pv.params.Logger.With(
		logfields.K8sNamespace, pol.Namespace,
		logfields.CiliumClusterwideNetworkPolicyName, pol.Name,
	)

	newPol := pol.DeepCopy()

	var errs error
	if newPol.Spec != nil {
		errs = errors.Join(errs, newPol.Spec.Sanitize())
	}
	for _, r := range newPol.Specs {
		errs = errors.Join(errs, r.Sanitize())
	}

	update := updateCondition(event.Object.Status.Conditions, errs)
	if update == nil {
		return nil
	}

	if errs != nil {
		log.DebugContext(ctx, "Detected invalid CCNP, setting condition", logfields.Error, errs)
	} else {
		log.DebugContext(ctx, "CCNP now valid, setting condition")
	}
	// Using the ApplyStatus subresource will prevent the generation from being bumped.
	_, err = pv.params.Clientset.CiliumV2().CiliumClusterwideNetworkPolicies().ApplyStatus(
		ctx,
		cilium_api_v2_apply.CiliumClusterwideNetworkPolicy(pol.Name).WithStatus(
			cilium_api_v2_apply.CiliumNetworkPolicyStatus().WithConditions(update),
		).WithResourceVersion(pol.ResourceVersion),
		metav1.ApplyOptions{FieldManager: "cilium-operator"},
	)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		log.ErrorContext(ctx, "failed to update CCNP status", logfields.Error, err)
	}

	return err
}

// updateCondition creates or updates the policy validation condition in Conditions, setting
// the transition time as necessary.
func updateCondition(conditions []cilium_api_v2.NetworkPolicyCondition, errs error) *cilium_api_v2_apply.NetworkPolicyConditionApplyConfiguration {
	newStatus := corev1.ConditionTrue
	newMessage := "Policy validation succeeded"
	if errs != nil {
		newStatus = corev1.ConditionFalse
		newMessage = errs.Error()
	}

	update := cilium_api_v2_apply.NetworkPolicyCondition().WithType(cilium_api_v2.PolicyConditionValid)

	// generate update from existing, if present
	for _, existing := range conditions {
		if existing.Type == cilium_api_v2.PolicyConditionValid {
			changed := false
			if existing.Status != newStatus {
				// set LTT and Status
				update = update.WithLastTransitionTime(slimv1.Now()).WithStatus(newStatus)
				changed = true
			}
			if existing.Message != newMessage {
				update = update.WithMessage(newMessage)
				changed = true
			}

			if changed {
				return update
			} else {
				return nil
			}
		}
	}

	// Otherwise, make an update from scratch
	update = update.WithLastTransitionTime(slimv1.Now()).WithMessage(newMessage).WithStatus(newStatus)
	return update
}
