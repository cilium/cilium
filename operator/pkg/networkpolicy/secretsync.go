// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkpolicy

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	ctrlRuntime "sigs.k8s.io/controller-runtime"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/pkg/networkpolicy/helpers"
	"github.com/cilium/cilium/operator/pkg/secretsync"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// SecretSyncCell manages the Network Policy related controllers.
var SecretSyncCell = cell.Module(
	"netpol-secretsync-watcher",
	"Watches network policy updates for TLS secrets to sync",

	cell.Config(secretSyncDefaultConfig),
	cell.Provide(registerCNPSecretSync),
	cell.Provide(registerCCNPSecretSync),
)

type SecretSyncConfig struct {
	EnablePolicySecretsSync bool
	PolicySecretsNamespace  string
}

var secretSyncDefaultConfig = SecretSyncConfig{
	EnablePolicySecretsSync: false,
	PolicySecretsNamespace:  "cilium-secrets",
}

func (def SecretSyncConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-policy-secrets-sync", def.EnablePolicySecretsSync, "Enables fan-in TLS secrets sync from multiple namespaces to singular namespace (specified by policy-secrets-namespace flag)")
	flags.String("policy-secrets-namespace", def.PolicySecretsNamespace, "Namespace where secrets used in TLS Interception will be synced to.")
}

type networkPolicyParams struct {
	cell.In

	Logger             *slog.Logger
	K8sClient          k8sClient.Clientset
	CtrlRuntimeManager ctrlRuntime.Manager
	Scheme             *runtime.Scheme

	AgentConfig         *option.DaemonConfig
	OperatorConfig      *operatorOption.OperatorConfig
	NetworkPolicyConfig SecretSyncConfig
}

// registerCNPSecretSync registers the Network Policy controllers for secret synchronization based on TLS secrets referenced
// by a CNP resource.
func registerCNPSecretSync(params networkPolicyParams) secretsync.SecretSyncRegistrationOut {
	if !params.NetworkPolicyConfig.EnablePolicySecretsSync {
		return secretsync.SecretSyncRegistrationOut{}
	}

	return secretsync.SecretSyncRegistrationOut{
		SecretSyncRegistration: &secretsync.SecretSyncRegistration{
			RefObject:            &cilium_api_v2.CiliumNetworkPolicy{},
			RefObjectEnqueueFunc: EnqueueTLSSecrets(params.CtrlRuntimeManager.GetClient(), params.Logger),
			RefObjectCheckFunc:   IsReferencedByCiliumNetworkPolicy,
			SecretsNamespace:     params.NetworkPolicyConfig.PolicySecretsNamespace,
		},
	}
}

// registerCCNPSecretSync registers the Network Policy controllers for secret synchronization based on TLS secrets referenced
// by a CCNP resource.
func registerCCNPSecretSync(params networkPolicyParams) secretsync.SecretSyncRegistrationOut {
	if !params.NetworkPolicyConfig.EnablePolicySecretsSync {
		return secretsync.SecretSyncRegistrationOut{}
	}

	return secretsync.SecretSyncRegistrationOut{
		SecretSyncRegistration: &secretsync.SecretSyncRegistration{
			RefObject:            &cilium_api_v2.CiliumClusterwideNetworkPolicy{},
			RefObjectEnqueueFunc: EnqueueTLSSecrets(params.CtrlRuntimeManager.GetClient(), params.Logger),
			RefObjectCheckFunc:   IsReferencedByCiliumClusterwideNetworkPolicy,
			SecretsNamespace:     params.NetworkPolicyConfig.PolicySecretsNamespace,
		},
	}
}

// EnqueueTLSSecrets returns a map function that, given a CiliumNetworkPolicy or CilumClusterwideNetworkPolicy,
// will return a slice of requests for any Secrets referenced in that CiliumNetworkPolicy.
//
// This includes both TLS secrets (Origination or Termination), plus Secrets used for storing header values.
func EnqueueTLSSecrets(c client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, obj client.Object) []reconcile.Request {
		objName := types.NamespacedName{
			Namespace: obj.GetNamespace(),
			Name:      obj.GetName(),
		}
		scopedLog := logger.With(
			logfields.Controller, "secrets",
			logfields.Resource, objName,
		)

		var specs []*api.Rule

		switch o := obj.(type) {
		case *cilium_api_v2.CiliumNetworkPolicy:
			if o.Spec != nil {
				specs = append(specs, o.Spec)
			}
			if len(o.Specs) > 0 {
				specs = append(specs, o.Specs...)
			}
			scopedLog = scopedLog.With(logfields.Kind, "CiliumNetworkPolicy")
		case *cilium_api_v2.CiliumClusterwideNetworkPolicy:
			if o.Spec != nil {
				specs = append(specs, o.Spec)
			}
			if len(o.Specs) > 0 {
				specs = append(specs, o.Specs...)
			}
			scopedLog = scopedLog.With(logfields.Kind, "CiliumClusterwideNetworkPolicy")
		}

		var reqs []reconcile.Request
		for _, rule := range specs {
			for _, egress := range rule.Egress {
				reqs = append(reqs, helpers.GetReferencedTLSSecretsFromPortRules(egress.ToPorts, scopedLog)...)
				reqs = append(reqs, helpers.GetReferencedSecretsFromHeaderRules(egress.ToPorts, scopedLog)...)
			}
			for _, ingress := range rule.Ingress {
				reqs = append(reqs, helpers.GetReferencedTLSSecretsFromPortRules(ingress.ToPorts, scopedLog)...)
				reqs = append(reqs, helpers.GetReferencedSecretsFromHeaderRules(ingress.ToPorts, scopedLog)...)
			}
		}
		return reqs
	})
}

func IsReferencedByCiliumNetworkPolicy(ctx context.Context, c client.Client, logger *slog.Logger, obj *corev1.Secret) bool {
	scopedLog := logger.With(
		logfields.Controller, "netpol-cnp-secretsync",
		logfields.Resource, obj.GetName(),
	)

	secretName := types.NamespacedName{
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
	}

	cnpList := &cilium_api_v2.CiliumNetworkPolicyList{}
	if err := c.List(ctx, cnpList); err != nil {
		scopedLog.Warn("Unable to list CiliumNetworkPolicies", logfields.Error, err)
		return false
	}

	for _, cnp := range cnpList.Items {

		var rules []*api.Rule

		if cnp.Spec != nil {
			rules = append(rules, cnp.Spec)
		}

		if len(cnp.Specs) > 0 {
			rules = append(rules, cnp.Specs...)
		}

		for _, rule := range rules {
			for _, egress := range rule.Egress {
				if helpers.IsSecretReferencedByPortRule(egress.ToPorts, scopedLog, secretName) {
					return true
				}
			}
			for _, ingress := range rule.Ingress {
				if helpers.IsSecretReferencedByPortRule(ingress.ToPorts, scopedLog, secretName) {
					return true
				}
			}
		}
	}
	return false
}

func IsReferencedByCiliumClusterwideNetworkPolicy(ctx context.Context, c client.Client, logger *slog.Logger, obj *corev1.Secret) bool {
	scopedLog := logger.With(
		logfields.Controller, "netpol-ccnp-secretsync",
		logfields.Resource, obj.GetName(),
	)

	secretName := types.NamespacedName{
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
	}

	ccnpList := &cilium_api_v2.CiliumClusterwideNetworkPolicyList{}
	if err := c.List(ctx, ccnpList); err != nil {
		scopedLog.Warn("Unable to list CiliumClusterwideNetworkPolicies", logfields.Error, err)
		return false
	}

	for _, ccnp := range ccnpList.Items {

		var rules []*api.Rule

		if ccnp.Spec != nil {
			rules = append(rules, ccnp.Spec)
		}

		if len(ccnp.Specs) > 0 {
			rules = append(rules, ccnp.Specs...)
		}

		for _, rule := range rules {
			for _, egress := range rule.Egress {
				if helpers.IsSecretReferencedByPortRule(egress.ToPorts, scopedLog, secretName) {
					return true
				}
			}
			for _, ingress := range rule.Ingress {
				if helpers.IsSecretReferencedByPortRule(ingress.ToPorts, scopedLog, secretName) {
					return true
				}
			}
		}
	}

	return false
}
