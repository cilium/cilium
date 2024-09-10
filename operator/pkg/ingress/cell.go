// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	networkingv1 "k8s.io/api/networking/v1"
	ctrlRuntime "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ingressTranslation "github.com/cilium/cilium/operator/pkg/model/translation/ingress"
	"github.com/cilium/cilium/operator/pkg/secretsync"
	"github.com/cilium/cilium/pkg/option"
)

// Cell manages the Kubernetes Ingress related controllers.
var Cell = cell.Module(
	"ingress",
	"Manages the Kubernetes Ingress controllers",

	cell.Config(IngressConfig{
		EnableIngressController:      false,
		EnforceIngressHTTPS:          true,
		EnableIngressProxyProtocol:   false,
		EnableIngressSecretsSync:     true,
		IngressSecretsNamespace:      "cilium-secrets",
		IngressDefaultRequestTimeout: time.Duration(0),
		IngressLBAnnotationPrefixes:  []string{"lbipam.cilium.io", "service.beta.kubernetes.io", "service.kubernetes.io", "cloud.google.com"},
		IngressSharedLBServiceName:   "cilium-ingress",
		IngressDefaultLBMode:         "dedicated",

		IngressHostnetworkEnabled:            false,
		IngressHostnetworkSharedListenerPort: 0,
		IngressHostnetworkNodelabelselector:  "",
	}),
	cell.Invoke(registerReconciler),
	cell.Provide(registerSecretSync),
)

type IngressConfig struct {
	KubeProxyReplacement                 string
	EnableNodePort                       bool
	EnableIngressController              bool
	EnforceIngressHTTPS                  bool
	EnableIngressProxyProtocol           bool
	EnableIngressSecretsSync             bool
	IngressSecretsNamespace              string
	IngressLBAnnotationPrefixes          []string
	IngressSharedLBServiceName           string
	IngressDefaultLBMode                 string
	IngressDefaultSecretNamespace        string
	IngressDefaultSecretName             string
	IngressDefaultRequestTimeout         time.Duration
	IngressHostnetworkEnabled            bool
	IngressHostnetworkSharedListenerPort uint32
	IngressHostnetworkNodelabelselector  string
	IngressDefaultXffNumTrustedHops      uint32
}

func (r IngressConfig) Flags(flags *pflag.FlagSet) {
	flags.String("kube-proxy-replacement", r.KubeProxyReplacement, "Enable only selected features (will panic if any selected feature cannot be enabled) (\"false\"), or enable all features (will panic if any feature cannot be enabled) (\"true\") (default \"false\")")
	flags.Bool("enable-node-port", r.EnableNodePort, "Enable NodePort type services by Cilium")
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
	flags.Duration("ingress-default-request-timeout", r.IngressDefaultRequestTimeout, "Default request timeout for Ingress.")
	flags.Bool("ingress-hostnetwork-enabled", r.IngressHostnetworkEnabled, "Exposes ingress listeners on the host network.")
	flags.Uint32("ingress-hostnetwork-shared-listener-port", r.IngressHostnetworkSharedListenerPort, "Port on the host network that gets used for the shared listener (HTTP, HTTPS & TLS passthrough)")
	flags.String("ingress-hostnetwork-nodelabelselector", r.IngressHostnetworkNodelabelselector, "Label selector that matches the nodes where the ingress listeners should be exposed. It's a list of comma-separated key-value label pairs. e.g. 'kubernetes.io/os=linux,kubernetes.io/hostname=kind-worker'")
	flags.Uint32("ingress-default-xff-num-trusted-hops", r.IngressDefaultXffNumTrustedHops, "The number of additional ingress proxy hops from the right side of the HTTP header to trust when determining the origin client's IP address.")
}

// IsEnabled returns true if the Ingress Controller is enabled.
func (r IngressConfig) IsEnabled() bool {
	return r.EnableIngressController
}

type ingressParams struct {
	cell.In

	Logger             *slog.Logger
	CtrlRuntimeManager ctrlRuntime.Manager
	AgentConfig        *option.DaemonConfig
	OperatorConfig     *operatorOption.OperatorConfig
	IngressConfig      IngressConfig
}

func registerReconciler(params ingressParams) error {
	if !params.IngressConfig.EnableIngressController {
		return nil
	}

	if params.IngressConfig.KubeProxyReplacement != option.KubeProxyReplacementTrue &&
		!params.IngressConfig.EnableNodePort {
		params.Logger.Warn("Ingress Controller support requires either kube-proxy-replacement or enable-node-port enabled")
		return nil
	}

	cecTranslator := translation.NewCECTranslator(
		params.IngressConfig.IngressSecretsNamespace,
		params.IngressConfig.EnableIngressProxyProtocol,
		false,
		false, // hostNameSuffixMatch
		params.OperatorConfig.ProxyIdleTimeoutSeconds,
		params.IngressConfig.IngressHostnetworkEnabled,
		translation.ParseNodeLabelSelector(params.IngressConfig.IngressHostnetworkNodelabelselector),
		params.AgentConfig.EnableIPv4,
		params.AgentConfig.EnableIPv6,
		params.IngressConfig.IngressDefaultXffNumTrustedHops,
	)

	dedicatedIngressTranslator := ingressTranslation.NewDedicatedIngressTranslator(cecTranslator, params.IngressConfig.IngressHostnetworkEnabled)

	reconciler := newIngressReconciler(
		params.Logger,
		params.CtrlRuntimeManager.GetClient(),

		cecTranslator,
		dedicatedIngressTranslator,

		operatorOption.Config.CiliumK8sNamespace,
		params.IngressConfig.IngressLBAnnotationPrefixes,
		params.IngressConfig.IngressSharedLBServiceName,
		params.IngressConfig.IngressDefaultLBMode,
		params.IngressConfig.IngressDefaultSecretNamespace,
		params.IngressConfig.IngressDefaultSecretName,
		params.IngressConfig.EnforceIngressHTTPS,
		params.IngressConfig.IngressDefaultRequestTimeout,

		params.IngressConfig.IngressHostnetworkEnabled,
		params.IngressConfig.IngressHostnetworkSharedListenerPort,
	)

	if err := reconciler.SetupWithManager(params.CtrlRuntimeManager); err != nil {
		return fmt.Errorf("failed to setup ingress reconciler: %w", err)
	}

	return nil
}

// registerSecretSync registers the Ingress Controller for secret synchronization based on TLS secrets referenced
// by a Cilium Ingress resource.
func registerSecretSync(params ingressParams) secretsync.SecretSyncRegistrationOut {
	if !params.IngressConfig.EnableIngressController || !params.IngressConfig.EnableIngressSecretsSync {
		return secretsync.SecretSyncRegistrationOut{}
	}

	registration := secretsync.SecretSyncRegistrationOut{
		SecretSyncRegistration: &secretsync.SecretSyncRegistration{
			RefObject:            &networkingv1.Ingress{},
			RefObjectEnqueueFunc: EnqueueReferencedTLSSecrets(params.CtrlRuntimeManager.GetClient(), params.Logger),
			RefObjectCheckFunc:   IsReferencedByCiliumIngress,
			SecretsNamespace:     params.IngressConfig.IngressSecretsNamespace,
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

	if params.IngressConfig.IngressDefaultSecretName != "" && params.IngressConfig.IngressDefaultSecretNamespace != "" {
		registration.SecretSyncRegistration.DefaultSecret = &secretsync.DefaultSecret{
			Namespace: params.IngressConfig.IngressDefaultSecretNamespace,
			Name:      params.IngressConfig.IngressDefaultSecretName,
		}
	}

	return registration
}
