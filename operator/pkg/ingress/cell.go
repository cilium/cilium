// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"context"
	"fmt"

	"github.com/spf13/pflag"

	operatorK8s "github.com/cilium/cilium/operator/k8s"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
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

func registerController(lc hive.Lifecycle, clientset k8sClient.Clientset, resources operatorK8s.Resources, config ingressConfig) error {
	if !config.EnableIngressController {
		return nil
	}

	ingressController, err := NewController(
		clientset,
		resources.IngressClasses,
		WithCiliumNamespace(operatorOption.Config.CiliumK8sNamespace),
		WithHTTPSEnforced(config.EnforceIngressHTTPS),
		WithProxyProtocol(config.EnableIngressProxyProtocol),
		WithSecretsSyncEnabled(config.EnableIngressSecretsSync),
		WithSecretsNamespace(config.IngressSecretsNamespace),
		WithLBAnnotationPrefixes(config.IngressLBAnnotationPrefixes),
		WithSharedLBServiceName(config.IngressSharedLBServiceName),
		WithDefaultLoadbalancerMode(config.IngressDefaultLBMode),
		WithDefaultSecretNamespace(config.IngressDefaultSecretNamespace),
		WithDefaultSecretName(config.IngressDefaultSecretName),
		WithIdleTimeoutSeconds(operatorOption.Config.ProxyIdleTimeoutSeconds),
	)
	if err != nil {
		return fmt.Errorf("failed to create ingress controller: %w", err)
	}

	ctx, cancelCtx := context.WithCancel(context.Background())

	lc.Append(hive.Hook{
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
