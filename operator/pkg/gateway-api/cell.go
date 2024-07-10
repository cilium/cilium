// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlRuntime "sigs.k8s.io/controller-runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	gatewayApiTranslation "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
	"github.com/cilium/cilium/operator/pkg/secretsync"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// Cell manages the Gateway API related controllers.
var Cell = cell.Module(
	"gateway-api",
	"Manages the Gateway API controllers",

	cell.Config(gatewayApiConfig{
		EnableGatewayAPISecretsSync:            true,
		EnableGatewayAPIProxyProtocol:          false,
		EnableGatewayAPIAppProtocol:            false,
		EnableGatewayAPIAlpn:                   false,
		GatewayAPIServiceExternalTrafficPolicy: "Cluster",
		GatewayAPISecretsNamespace:             "cilium-secrets",
		GatewayAPIXffNumTrustedHops:            0,

		GatewayAPIHostnetworkEnabled:           false,
		GatewayAPIHostnetworkNodelabelselector: "",
	}),
	cell.Invoke(initGatewayAPIController),
	cell.Provide(registerSecretSync),
)

var requiredGVK = []schema.GroupVersionKind{
	gatewayv1.SchemeGroupVersion.WithKind("gatewayclasses"),
	gatewayv1.SchemeGroupVersion.WithKind("gateways"),
	gatewayv1.SchemeGroupVersion.WithKind("httproutes"),
	gatewayv1.SchemeGroupVersion.WithKind("grpcroutes"),
	gatewayv1beta1.SchemeGroupVersion.WithKind("referencegrants"),
	gatewayv1alpha2.SchemeGroupVersion.WithKind("tlsroutes"),
}

type gatewayApiConfig struct {
	KubeProxyReplacement string
	EnableNodePort       bool

	EnableGatewayAPISecretsSync            bool
	EnableGatewayAPIProxyProtocol          bool
	EnableGatewayAPIAppProtocol            bool
	EnableGatewayAPIAlpn                   bool
	GatewayAPIServiceExternalTrafficPolicy string
	GatewayAPISecretsNamespace             string
	GatewayAPIXffNumTrustedHops            uint32

	GatewayAPIHostnetworkEnabled           bool
	GatewayAPIHostnetworkNodelabelselector string
}

func (r gatewayApiConfig) Flags(flags *pflag.FlagSet) {
	flags.String("kube-proxy-replacement", r.KubeProxyReplacement, "Enable only selected features (will panic if any selected feature cannot be enabled) (\"false\"), or enable all features (will panic if any feature cannot be enabled) (\"true\") (default \"false\")")
	flags.Bool("enable-node-port", r.EnableNodePort, "Enable NodePort type services by Cilium")

	flags.Bool("enable-gateway-api-secrets-sync", r.EnableGatewayAPISecretsSync, "Enables fan-in TLS secrets sync from multiple namespaces to singular namespace (specified by gateway-api-secrets-namespace flag)")
	flags.Bool("enable-gateway-api-proxy-protocol", r.EnableGatewayAPIProxyProtocol, "Enable proxy protocol for all GatewayAPI listeners. Note that _only_ Proxy protocol traffic will be accepted once this is enabled.")
	flags.Bool("enable-gateway-api-app-protocol", r.EnableGatewayAPIAppProtocol, "Enables Backend Protocol selection (GEP-1911) for Gateway API via appProtocol")
	flags.Bool("enable-gateway-api-alpn", r.EnableGatewayAPIAlpn, "Enables exposing ALPN with HTTP2 and HTTP/1.1 support for Gateway API")
	flags.Uint32("gateway-api-xff-num-trusted-hops", r.GatewayAPIXffNumTrustedHops, "The number of additional GatewayAPI proxy hops from the right side of the HTTP header to trust when determining the origin client's IP address.")
	flags.String("gateway-api-service-externaltrafficpolicy", r.GatewayAPIServiceExternalTrafficPolicy, "Kubernetes LoadBalancer Service externalTrafficPolicy for all Gateway instances.")
	flags.String("gateway-api-secrets-namespace", r.GatewayAPISecretsNamespace, "Namespace having tls secrets used by CEC for Gateway API")
	flags.Bool("gateway-api-hostnetwork-enabled", r.GatewayAPIHostnetworkEnabled, "Exposes Gateway listeners on the host network.")
	flags.String("gateway-api-hostnetwork-nodelabelselector", r.GatewayAPIHostnetworkNodelabelselector, "Label selector that matches the nodes where the gateway listeners should be exposed. It's a list of comma-separated key-value label pairs. e.g. 'kubernetes.io/os=linux,kubernetes.io/hostname=kind-worker'")
}

type gatewayAPIParams struct {
	cell.In

	Logger             *slog.Logger
	K8sClient          k8sClient.Clientset
	CtrlRuntimeManager ctrlRuntime.Manager
	Scheme             *runtime.Scheme

	AgentConfig      *option.DaemonConfig
	OperatorConfig   *operatorOption.OperatorConfig
	GatewayApiConfig gatewayApiConfig
}

func initGatewayAPIController(params gatewayAPIParams) error {
	if !operatorOption.Config.EnableGatewayAPI {
		return nil
	}

	if params.GatewayApiConfig.KubeProxyReplacement != option.KubeProxyReplacementTrue &&
		!params.GatewayApiConfig.EnableNodePort {
		params.Logger.Warn("Gateway API support requires either kube-proxy-replacement or enable-node-port enabled")
		return nil
	}

	if err := validateExternalTrafficPolicy(params); err != nil {
		return err
	}

	params.Logger.Info("Checking for required GatewayAPI resources", "requiredGVK", requiredGVK)
	if err := checkRequiredCRDs(context.Background(), params.K8sClient); err != nil {
		params.Logger.Error("Required GatewayAPI resources are not found, please refer to docs for installation instructions", logfields.Error, err)
		return nil
	}

	if err := registerGatewayAPITypesToScheme(params.Scheme); err != nil {
		return err
	}

	if err := registerMCSAPITypesToScheme(params.K8sClient, params.Scheme, params.Logger); err != nil {
		return err
	}

	cecTranslator := translation.NewCECTranslator(
		params.GatewayApiConfig.GatewayAPISecretsNamespace,
		params.GatewayApiConfig.EnableGatewayAPIProxyProtocol,
		params.GatewayApiConfig.EnableGatewayAPIAppProtocol,
		true, // hostNameSuffixMatch
		params.OperatorConfig.ProxyIdleTimeoutSeconds,
		params.GatewayApiConfig.GatewayAPIHostnetworkEnabled,
		translation.ParseNodeLabelSelector(params.GatewayApiConfig.GatewayAPIHostnetworkNodelabelselector),
		params.AgentConfig.EnableIPv4,
		params.AgentConfig.EnableIPv6,
		params.GatewayApiConfig.GatewayAPIXffNumTrustedHops,
	)

	cecTranslator.WithUseAlpn(params.GatewayApiConfig.EnableGatewayAPIAlpn)

	gatewayAPITranslator := gatewayApiTranslation.NewTranslator(
		cecTranslator,
		params.GatewayApiConfig.GatewayAPIHostnetworkEnabled,
		params.GatewayApiConfig.GatewayAPIServiceExternalTrafficPolicy,
	)

	if err := registerReconcilers(
		params.CtrlRuntimeManager,
		gatewayAPITranslator,
		params.Logger,
	); err != nil {
		return fmt.Errorf("failed to create gateway controller: %w", err)
	}

	return nil
}

// registerSecretSync registers the Gateway API for secret synchronization based on TLS secrets referenced
// by a Cilium Gateway resource.
func registerSecretSync(params gatewayAPIParams) secretsync.SecretSyncRegistrationOut {
	if err := checkRequiredCRDs(context.Background(), params.K8sClient); err != nil {
		return secretsync.SecretSyncRegistrationOut{}
	}

	if !operatorOption.Config.EnableGatewayAPI || !params.GatewayApiConfig.EnableGatewayAPISecretsSync {
		return secretsync.SecretSyncRegistrationOut{}
	}

	return secretsync.SecretSyncRegistrationOut{
		SecretSyncRegistration: &secretsync.SecretSyncRegistration{
			RefObject:            &gatewayv1.Gateway{},
			RefObjectEnqueueFunc: EnqueueTLSSecrets(params.CtrlRuntimeManager.GetClient(), params.Logger),
			RefObjectCheckFunc:   IsReferencedByCiliumGateway,
			SecretsNamespace:     params.GatewayApiConfig.GatewayAPISecretsNamespace,
		},
	}
}

func validateExternalTrafficPolicy(params gatewayAPIParams) error {
	if params.GatewayApiConfig.GatewayAPIHostnetworkEnabled && params.GatewayApiConfig.GatewayAPIServiceExternalTrafficPolicy != "" {
		params.Logger.Warn("Gateway API host networking is enabled, externalTrafficPolicy will be ignored.")
		return nil
	} else if params.GatewayApiConfig.GatewayAPIServiceExternalTrafficPolicy == string(corev1.ServiceExternalTrafficPolicyCluster) ||
		params.GatewayApiConfig.GatewayAPIServiceExternalTrafficPolicy == string(corev1.ServiceExternalTrafficPolicyLocal) {
		return nil
	}
	return fmt.Errorf("invalid externalTrafficPolicy: %s", params.GatewayApiConfig.GatewayAPIServiceExternalTrafficPolicy)
}

func checkCRD(ctx context.Context, clientset k8sClient.Clientset, gvk schema.GroupVersionKind) error {
	if !clientset.IsEnabled() {
		return nil
	}

	crd, err := clientset.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, gvk.GroupKind().String(), metav1.GetOptions{})
	if err != nil {
		return err
	}

	found := false
	for _, v := range crd.Spec.Versions {
		if v.Name == gvk.Version {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("CRD %q does not have version %q", gvk.GroupKind().String(), gvk.Version)
	}

	return nil
}

func checkRequiredCRDs(ctx context.Context, clientset k8sClient.Clientset) error {
	var res error
	for _, gvk := range requiredGVK {
		if err := checkCRD(ctx, clientset, gvk); err != nil {
			res = errors.Join(res, err)
		}
	}
	return res
}

// registerReconcilers registers the Gateway API reconcilers to the controller-runtime library manager.
func registerReconcilers(mgr ctrlRuntime.Manager, translator translation.Translator, logger *slog.Logger) error {
	reconcilers := []interface {
		SetupWithManager(mgr ctrlRuntime.Manager) error
	}{
		newGatewayClassReconciler(mgr, logger),
		newGatewayReconciler(mgr, translator, logger),
		newReferenceGrantReconciler(mgr, logger),
		newHTTPRouteReconciler(mgr, logger),
		newGammaHttpRouteReconciler(mgr, translator, logger),
		newGRPCRouteReconciler(mgr, logger),
		newTLSRouteReconciler(mgr, logger),
	}

	for _, r := range reconcilers {
		if err := r.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("failed to setup reconciler: %w", err)
		}
	}

	return nil
}

func registerGatewayAPITypesToScheme(scheme *runtime.Scheme) error {
	for gv, f := range map[fmt.Stringer]func(s *runtime.Scheme) error{
		gatewayv1.GroupVersion:       gatewayv1.AddToScheme,
		gatewayv1beta1.GroupVersion:  gatewayv1beta1.AddToScheme,
		gatewayv1alpha2.GroupVersion: gatewayv1alpha2.AddToScheme,
	} {
		if err := f(scheme); err != nil {
			return fmt.Errorf("failed to add types from %s to scheme: %w", gv, err)
		}
	}

	return nil
}

func registerMCSAPITypesToScheme(clientset k8sClient.Clientset, scheme *runtime.Scheme, logger *slog.Logger) error {
	serviceImportSupport := checkCRD(context.Background(), clientset, mcsapiv1alpha1.SchemeGroupVersion.WithKind("serviceimports")) == nil
	logger.Info("Multi-cluster Service API ServiceImport GatewayAPI integration", "enabled", serviceImportSupport)
	if serviceImportSupport {
		return mcsapiv1alpha1.AddToScheme(scheme)
	}

	return nil
}
