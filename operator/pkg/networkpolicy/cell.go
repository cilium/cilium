// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// The networkpolicy package performs basic policy validation and updates
// the policy's Status field as relevant.

package networkpolicy

import (
	"context"
	"errors"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
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

	Logger       logrus.FieldLogger
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
	log := pv.params.Logger.WithFields(logrus.Fields{
		logfields.K8sNamespace:            pol.Namespace,
		logfields.CiliumNetworkPolicyName: pol.Name,
	})

	var errs error
	if pol.Spec != nil {
		errs = errors.Join(pol.Spec.Sanitize())
	}
	for _, r := range pol.Specs {
		errs = errors.Join(r.Sanitize())
	}

	newPol := pol.DeepCopy()
	newPol.Status.Conditions = updateCondition(event.Object.Status.Conditions, errs)
	if newPol.Status.DeepEqual(&pol.Status) {
		return nil
	}

	if errs != nil {
		log.WithField(logfields.Error, errs).Debug("Detected invalid CNP, setting condition")
	} else {
		log.Debug("CNP now valid, setting condition")
	}
	// Using the UpdateStatus subresource will prevent the generation from being bumped.
	_, err = pv.params.Clientset.CiliumV2().CiliumNetworkPolicies(pol.Namespace).UpdateStatus(
		ctx,
		newPol,
		metav1.UpdateOptions{},
	)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		log.WithError(err).Error("failed to update CNP status")
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
	log := pv.params.Logger.WithFields(logrus.Fields{
		logfields.K8sNamespace:                       pol.Namespace,
		logfields.CiliumClusterwideNetworkPolicyName: pol.Name,
	})

	var errs error
	if pol.Spec != nil {
		errs = errors.Join(pol.Spec.Sanitize())
	}
	for _, r := range pol.Specs {
		errs = errors.Join(r.Sanitize())
	}

	newPol := pol.DeepCopy()
	newPol.Status.Conditions = updateCondition(event.Object.Status.Conditions, errs)
	if newPol.Status.DeepEqual(&pol.Status) {
		return nil
	}

	if errs != nil {
		log.WithField(logfields.Error, errs).Debug("Detected invalid CCNP, setting condition")
	} else {
		log.Debug("CCNP now valid, setting condition")
	}
	// Using the UpdateStatus subresource will prevent the generation from being bumped.
	_, err = pv.params.Clientset.CiliumV2().CiliumClusterwideNetworkPolicies().UpdateStatus(
		ctx,
		newPol,
		metav1.UpdateOptions{},
	)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		log.WithError(err).Error("failed to update CCNP status")
	}

	return err
}

// updateCondition creates or updates the policy validation condition in Conditions, setting
// the transition time as necessary.
func updateCondition(conditions []cilium_api_v2.NetworkPolicyCondition, errs error) []cilium_api_v2.NetworkPolicyCondition {
	wantCondition := corev1.ConditionTrue
	message := "Policy validation succeeded"
	if errs != nil {
		wantCondition = corev1.ConditionFalse
		message = errs.Error()
	}

	// look for the condition type already existing.
	foundIdx := -1
	for i, cond := range conditions {
		if cond.Type == cilium_api_v2.PolicyConditionValid {
			foundIdx = i
			// If nothing important changed, short-circuit
			if cond.Status == wantCondition && cond.Message == message {
				return conditions
			}
			break
		}
	}

	// Otherwise, set / update the condition
	newCond := cilium_api_v2.NetworkPolicyCondition{
		Type:               cilium_api_v2.PolicyConditionValid,
		Status:             wantCondition,
		LastTransitionTime: slimv1.Now(),
		Message:            message,
	}

	out := append([]cilium_api_v2.NetworkPolicyCondition{}, conditions...)

	if foundIdx >= 0 {
		// If the status did not change (just the message), don't bump the
		// LastTransitionTime.
		if out[foundIdx].Status == newCond.Status {
			newCond.LastTransitionTime = out[foundIdx].LastTransitionTime
		}
		out[foundIdx] = newCond
	} else {
		out = append(out, newCond)
	}
	return out
}
