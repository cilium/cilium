// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	networkingv1 "k8s.io/api/networking/v1"
	ctrlRuntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	operatorK8s "github.com/cilium/cilium/operator/k8s"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/pkg/secretsync"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/client"
)

// Cell manages the Kubernetes Ingress related controllers.
var Cell = cell.Module(
	"ingress",
	"Manages the Kubernetes Ingress controllers",

	cell.Config(ingressConfig{
		EnableIngressController:     false,
		EnforceIngressHTTPS:         true,
		EnableIngressProxyProtocol:  false,
		EnableIngressSecretsSync:    true,
		IngressSecretsNamespace:     "cilium-secrets",
		IngressLBAnnotationPrefixes: []string{"service.beta.kubernetes.io", "service.kubernetes.io", "cloud.google.com"},
		IngressSharedLBServiceName:  "cilium-ingress",
		IngressDefaultLBMode:        "dedicated",
	}),
	cell.Invoke(registerController),
	cell.Provide(registerSecretSync),
)

type ingressConfig struct {
	EnableIngressController       bool
	EnforceIngressHTTPS           bool
	EnableIngressProxyProtocol    bool
	EnableIngressSecretsSync      bool
	IngressSecretsNamespace       string
	IngressLBAnnotationPrefixes   []string
	IngressSharedLBServiceName    string
	IngressDefaultLBMode          string
	IngressDefaultSecretNamespace string
	IngressDefaultSecretName      string
}

func (r ingressConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-ingress-controller", r.EnableIngressController, "Enables cilium ingress controller. This must be enabled along with enable-envoy-config in cilium agent.")
	flags.Bool("enforce-ingress-https", r.EnforceIngressHTTPS, "Enforces https for host having matching TLS host in Ingress. Incoming traffic to http listener will return 308 http error code with respective location in header.")
	flags.Bool("enable-ingress-proxy-protocol", r.EnableIngressProxyProtocol, "Enable proxy protocol for all Ingress listeners. Note that _only_ Proxy protocol traffic will be accepted once this is enabled.")
	flags.Bool("enable-ingress-secrets-sync", r.EnableIngressSecretsSync, "Enables fan-in TLS secrets from multiple namespaces to singular namespace (specified by ingress-secrets-namespace flag)")
	flags.String("ingress-secrets-namespace", r.IngressSecretsNamespace, "Namespace having tls secrets used by Ingress and CEC.")
	flags.StringSlice("ingress-lb-annotation-prefixes", r.IngressLBAnnotationPrefixes, "Annotations and labels which are needed to propagate from Ingress to the Load Balancer.")
	flags.String("ingress-shared-lb-service-name", r.IngressSharedLBServiceName, "Name of shared LB service name for Ingress.")
	flags.String("ingress-default-lb-mode", r.IngressDefaultLBMode, "Default loadbalancer mode for Ingress. Applicable values: dedicated, shared")
	flags.String("ingress-default-secret-namespace", r.IngressDefaultSecretNamespace, "Default secret namespace for Ingress.")
	flags.String("ingress-default-secret-name", r.IngressDefaultSecretName, "Default secret name for Ingress.")
}

type ingressParams struct {
	cell.In

	Logger    logrus.FieldLogger
	Lifecycle hive.Lifecycle

	Config             ingressConfig
	K8sClient          client.Clientset
	CtrlRuntimeManager ctrlRuntime.Manager
	Resources          operatorK8s.Resources
}

func registerController(params ingressParams) error {
	if !params.Config.EnableIngressController {
		return nil
	}

	ingressController, err := NewController(
		params.K8sClient,
		params.Resources.IngressClasses,
		WithCiliumNamespace(operatorOption.Config.CiliumK8sNamespace),
		WithHTTPSEnforced(params.Config.EnforceIngressHTTPS),
		WithProxyProtocol(params.Config.EnableIngressProxyProtocol),
		WithSecretsNamespace(params.Config.IngressSecretsNamespace),
		WithLBAnnotationPrefixes(params.Config.IngressLBAnnotationPrefixes),
		WithSharedLBServiceName(params.Config.IngressSharedLBServiceName),
		WithDefaultLoadbalancerMode(params.Config.IngressDefaultLBMode),
		WithDefaultSecretNamespace(params.Config.IngressDefaultSecretNamespace),
		WithDefaultSecretName(params.Config.IngressDefaultSecretName),
		WithIdleTimeoutSeconds(operatorOption.Config.ProxyIdleTimeoutSeconds),
	)
	if err != nil {
		return fmt.Errorf("failed to create ingress controller: %w", err)
	}

	ctx, cancelCtx := context.WithCancel(context.Background())

	params.Lifecycle.Append(hive.Hook{
		OnStart: func(_ hive.HookContext) error {
			go ingressController.Run(ctx)
			return nil
		},
		OnStop: func(hive.HookContext) error {
			cancelCtx()
			return nil
		},
	})

	return nil
}

// registerSecretSync registers the Ingress Controller for secret synchronization based on TLS secrets referenced
// by a Cilium Ingress resource.
func registerSecretSync(params ingressParams) secretsync.SecretSyncRegistrationOut {
	if !params.Config.EnableIngressController || !params.Config.EnableIngressSecretsSync {
		return secretsync.SecretSyncRegistrationOut{}
	}

	registration := secretsync.SecretSyncRegistrationOut{
		SecretSyncRegistration: &secretsync.SecretSyncRegistration{
			RefObject:            &networkingv1.Ingress{},
			RefObjectEnqueueFunc: EnqueueReferencedTLSSecrets(params.CtrlRuntimeManager.GetClient(), params.Logger),
			RefObjectCheckFunc:   IsReferencedByCiliumIngress,
			SecretsNamespace:     params.Config.IngressSecretsNamespace,
			// In addition to changed Ingresses an additional watch on IngressClass gets added.
			// Its purpose is to detect any changes regarding the default IngressClass
			// (that is marked via annotation).
			AdditionalWatches: []secretsync.AdditionalWatch{
				{
					RefObject:            &networkingv1.IngressClass{},
					RefObjectEnqueueFunc: enqueueAllSecrets(params.CtrlRuntimeManager.GetClient()),
					RefObjectWatchOptions: []builder.WatchesOption{
						builder.WithPredicates(predicate.AnnotationChangedPredicate{}),
					},
				},
			},
		},
	}

	if params.Config.IngressDefaultSecretName != "" && params.Config.IngressDefaultSecretNamespace != "" {
		registration.SecretSyncRegistration.DefaultSecret = &secretsync.DefaultSecret{
			Namespace: params.Config.IngressDefaultSecretNamespace,
			Name:      params.Config.IngressDefaultSecretName,
		}
	}

	return registration
}
