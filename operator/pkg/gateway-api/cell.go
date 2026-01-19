// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"syscall"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlRuntime "sigs.k8s.io/controller-runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
	mcsapiv1alpha1 "sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	gatewayApiTranslation "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
	"github.com/cilium/cilium/operator/pkg/secretsync"
	"github.com/cilium/cilium/pkg/backoff"
	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
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

	// Private provider for preconditions - consumed by both initGatewayAPIController
	// and registerSecretSync to ensure consistent behavior
	cell.ProvidePrivate(newGatewayAPIPreconditions),

	cell.Invoke(initGatewayAPIController),
	cell.Provide(registerSecretSync),
)

var requiredGVKs = []schema.GroupVersionKind{
	gatewayv1.SchemeGroupVersion.WithKind(helpers.GatewayClassKind),
	gatewayv1.SchemeGroupVersion.WithKind(helpers.GatewayKind),
	gatewayv1.SchemeGroupVersion.WithKind(helpers.HTTPRouteKind),
	gatewayv1.SchemeGroupVersion.WithKind(helpers.GRPCRouteKind),
	gatewayv1beta1.SchemeGroupVersion.WithKind(helpers.ReferenceGrantKind),
}

var optionalGVKs = []schema.GroupVersionKind{
	gatewayv1alpha2.SchemeGroupVersion.WithKind(helpers.TLSRouteKind),
	mcsapiv1alpha1.SchemeGroupVersion.WithKind(helpers.ServiceImportKind),
}

// gatewayAPIPreconditions holds the result of Gateway API precondition checks.
// This is provided privately and consumed by both initGatewayAPIController
// and registerSecretSync to ensure consistent behavior.
type gatewayAPIPreconditions struct {
	// Enabled indicates all preconditions are met for Gateway API
	Enabled bool
	// InstalledKinds contains the GVKs of installed Gateway API CRDs
	InstalledKinds []schema.GroupVersionKind
}

// preconditionParams contains dependencies for checking Gateway API preconditions.
type preconditionParams struct {
	cell.In

	Logger           *slog.Logger
	K8sClient        k8sClient.Clientset
	Health           cell.Health
	OperatorConfig   *operatorOption.OperatorConfig
	GatewayApiConfig gatewayApiConfig
}

// newGatewayAPIPreconditions checks all Gateway API preconditions and returns
// the result. This includes config checks, kube-proxy-replacement check,
// external traffic policy validation, and CRD discovery with retry logic.
func newGatewayAPIPreconditions(params preconditionParams) (*gatewayAPIPreconditions, error) {
	if !operatorOption.Config.EnableGatewayAPI {
		return &gatewayAPIPreconditions{Enabled: false}, nil
	}

	if !params.OperatorConfig.KubeProxyReplacement {
		params.Logger.Warn("Gateway API support requires kube-proxy-replacement enabled")
		return &gatewayAPIPreconditions{Enabled: false}, nil
	}

	if err := validateExternalTrafficPolicy(params.GatewayApiConfig, params.Logger); err != nil {
		return nil, err
	}

	params.Logger.Info(
		"Checking for required and optional GatewayAPI resources",
		logfields.RequiredGVK, requiredGVKs,
		logfields.OptionalGVK, optionalGVKs,
	)

	// Configure exponential backoff for CRD discovery.
	// This allows the operator to recover if API server is temporarily unavailable at startup.
	bo := backoff.Exponential{
		Logger: params.Logger,
		Min:    200 * time.Millisecond,
		Max:    5 * time.Second,
		Factor: 2.0,
		Jitter: true,
		Name:   "gateway-api-crd-discovery",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for {
		installedKinds, err := checkCRDs(ctx, params.K8sClient, params.Logger, requiredGVKs, optionalGVKs)
		if err == nil {
			params.Health.OK("Gateway API CRDs discovered")
			return &gatewayAPIPreconditions{
				Enabled:        true,
				InstalledKinds: installedKinds,
			}, nil
		}

		if !isTransientError(err) {
			params.Logger.Error(
				"Required GatewayAPI resources are not found, please refer to docs for installation instructions",
				logfields.Error, err,
			)
			params.Health.Degraded("Gateway API CRDs not installed", err)
			return &gatewayAPIPreconditions{Enabled: false}, nil
		}

		params.Logger.Warn(
			"Failed to check GatewayAPI CRDs due to transient error, will retry",
			logfields.Error, err,
		)
		params.Health.Degraded("Gateway API initialization pending - API server unreachable", err)

		if err := bo.Wait(ctx); err != nil {
			return nil, err
		}
	}
}

type gatewayApiConfig struct {
	EnableGatewayAPISecretsSync            bool
	EnableGatewayAPIProxyProtocol          bool
	EnableGatewayAPIAppProtocol            bool
	EnableGatewayAPIAlpn                   bool
	GatewayAPIServiceExternalTrafficPolicy string
	GatewayAPISecretsNamespace             string
	GatewayAPIXffNumTrustedHops            uint32
	GatewayAPIUseRemoteAddress             bool

	GatewayAPIHostnetworkEnabled           bool
	GatewayAPIHostnetworkNodelabelselector string
}

func (r gatewayApiConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-gateway-api-secrets-sync", r.EnableGatewayAPISecretsSync, "Enables fan-in TLS secrets sync from multiple namespaces to singular namespace (specified by gateway-api-secrets-namespace flag)")
	flags.Bool("enable-gateway-api-proxy-protocol", r.EnableGatewayAPIProxyProtocol, "Enable proxy protocol for all GatewayAPI listeners. Note that _only_ Proxy protocol traffic will be accepted once this is enabled.")
	flags.Bool("enable-gateway-api-app-protocol", r.EnableGatewayAPIAppProtocol, "Enables Backend Protocol selection (GEP-1911) for Gateway API via appProtocol")
	flags.Bool("enable-gateway-api-alpn", r.EnableGatewayAPIAlpn, "Enables exposing ALPN with HTTP2 and HTTP/1.1 support for Gateway API")
	flags.Bool("gateway-api-use-remote-address", r.GatewayAPIUseRemoteAddress, "Use the remote address as the client IP address when determining the origin client's IP address.")
	flags.Uint32("gateway-api-xff-num-trusted-hops", r.GatewayAPIXffNumTrustedHops, "The number of additional GatewayAPI proxy hops from the right side of the HTTP header to trust when determining the origin client's IP address.")
	flags.String("gateway-api-service-externaltrafficpolicy", r.GatewayAPIServiceExternalTrafficPolicy, "Kubernetes LoadBalancer Service externalTrafficPolicy for all Gateway instances.")
	flags.String("gateway-api-secrets-namespace", r.GatewayAPISecretsNamespace, "Namespace having tls secrets used by CEC for Gateway API")
	flags.Bool("gateway-api-hostnetwork-enabled", r.GatewayAPIHostnetworkEnabled, "Exposes Gateway listeners on the host network.")
	flags.String("gateway-api-hostnetwork-nodelabelselector", r.GatewayAPIHostnetworkNodelabelselector, "Label selector that matches the nodes where the gateway listeners should be exposed. It's a list of comma-separated key-value label pairs. e.g. 'kubernetes.io/os=linux,kubernetes.io/hostname=kind-worker'")
}

type gatewayAPIParams struct {
	cell.In

	Logger             *slog.Logger
	CtrlRuntimeManager ctrlRuntime.Manager
	Scheme             *runtime.Scheme

	AgentConfig      *option.DaemonConfig
	OperatorConfig   *operatorOption.OperatorConfig
	MCSAPIConfig     mcsapitypes.MCSAPIConfig
	GatewayApiConfig gatewayApiConfig

	// Preconditions is injected from private provider
	Preconditions *gatewayAPIPreconditions
}

func initGatewayAPIController(params gatewayAPIParams) error {
	if !params.Preconditions.Enabled {
		return nil
	}

	installedKinds := params.Preconditions.InstalledKinds

	// Handle MCS API CRDs
	if params.MCSAPIConfig.ShouldInstallMCSAPICrds() && !slices.Contains(installedKinds, mcsapiv1alpha1.SchemeGroupVersion.WithKind(helpers.ServiceImportKind)) {
		// We can just assume ServiceImport are installed if we are going to install it
		installedKinds = append(installedKinds, mcsapiv1alpha1.SchemeGroupVersion.WithKind(helpers.ServiceImportKind))
	}

	if err := registerGatewayAPITypesToScheme(params.Scheme, installedKinds); err != nil {
		return err
	}

	if err := v2alpha1.AddToScheme(params.Scheme); err != nil {
		return err
	}

	cfg := translation.Config{
		SecretsNamespace: params.GatewayApiConfig.GatewayAPISecretsNamespace,
		ServiceConfig: translation.ServiceConfig{
			ExternalTrafficPolicy: params.GatewayApiConfig.GatewayAPIServiceExternalTrafficPolicy,
		},
		HostNetworkConfig: translation.HostNetworkConfig{
			Enabled:           params.GatewayApiConfig.GatewayAPIHostnetworkEnabled,
			NodeLabelSelector: translation.ParseNodeLabelSelector(params.GatewayApiConfig.GatewayAPIHostnetworkNodelabelselector),
		},
		IPConfig: translation.IPConfig{
			IPv4Enabled: params.AgentConfig.EnableIPv4,
			IPv6Enabled: params.AgentConfig.EnableIPv6,
		},
		ListenerConfig: translation.ListenerConfig{
			UseProxyProtocol:         params.GatewayApiConfig.EnableGatewayAPIProxyProtocol,
			UseAlpn:                  params.GatewayApiConfig.EnableGatewayAPIAlpn,
			StreamIdleTimeoutSeconds: params.OperatorConfig.ProxyStreamIdleTimeoutSeconds,
		},
		ClusterConfig: translation.ClusterConfig{
			IdleTimeoutSeconds: params.OperatorConfig.ProxyIdleTimeoutSeconds,
			UseAppProtocol:     params.GatewayApiConfig.EnableGatewayAPIAppProtocol,
		},
		RouteConfig: translation.RouteConfig{
			HostNameSuffixMatch: true,
		},
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
			XFFNumTrustedHops: params.GatewayApiConfig.GatewayAPIXffNumTrustedHops,
			UseRemoteAddress:  params.GatewayApiConfig.GatewayAPIUseRemoteAddress,
		},
	}
	cecTranslator := translation.NewCECTranslator(cfg)

	gatewayAPITranslator := gatewayApiTranslation.NewTranslator(cecTranslator, cfg)

	if err := registerReconcilers(
		params.CtrlRuntimeManager,
		gatewayAPITranslator,
		params.Logger,
		installedKinds,
	); err != nil {
		return fmt.Errorf("failed to create gateway controller: %w", err)
	}

	return nil
}

// secretSyncParams contains dependencies for secret synchronization registration.
type secretSyncParams struct {
	cell.In

	Logger             *slog.Logger
	CtrlRuntimeManager ctrlRuntime.Manager
	GatewayApiConfig   gatewayApiConfig

	// Preconditions is injected from private provider
	Preconditions *gatewayAPIPreconditions
}

// registerSecretSync registers the Gateway API for secret synchronization based on TLS secrets referenced
// by a Cilium Gateway resource.
func registerSecretSync(params secretSyncParams) secretsync.SecretSyncRegistrationOut {
	if !params.Preconditions.Enabled {
		return secretsync.SecretSyncRegistrationOut{}
	}

	if !params.GatewayApiConfig.EnableGatewayAPISecretsSync {
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

func validateExternalTrafficPolicy(cfg gatewayApiConfig, logger *slog.Logger) error {
	if cfg.GatewayAPIHostnetworkEnabled && cfg.GatewayAPIServiceExternalTrafficPolicy != "" {
		logger.Warn("Gateway API host networking is enabled, externalTrafficPolicy will be ignored.")
		return nil
	} else if cfg.GatewayAPIServiceExternalTrafficPolicy == string(corev1.ServiceExternalTrafficPolicyCluster) ||
		cfg.GatewayAPIServiceExternalTrafficPolicy == string(corev1.ServiceExternalTrafficPolicyLocal) {
		return nil
	}
	return fmt.Errorf("invalid externalTrafficPolicy: %s", cfg.GatewayAPIServiceExternalTrafficPolicy)
}

// isTransientError returns true if the error is temporary and retryable
// (network issues, API server overload), vs permanent errors (CRD not installed).
// This is used to determine whether to retry Gateway API CRD discovery.
func isTransientError(err error) bool {
	if err == nil {
		return false
	}

	// Check for Kubernetes API server errors that are transient
	if k8serrors.IsServerTimeout(err) ||
		k8serrors.IsServiceUnavailable(err) ||
		k8serrors.IsTooManyRequests(err) ||
		k8serrors.IsTimeout(err) {
		return true
	}

	// Check for network-level errors (connection refused, reset, host unreachable)
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.EHOSTUNREACH, syscall.ENETUNREACH:
			return true
		}
	}

	return false
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

// checkCRDs checks if required and optional CRDs are present in the cluster,
// returns an error if the required CRDs are not installed, and returns the
// schema.GroupVersionKind of any optional CRDs that are installed.
func checkCRDs(ctx context.Context, clientset k8sClient.Clientset, logger *slog.Logger, requiredGVKs, optionalGVKs []schema.GroupVersionKind) ([]schema.GroupVersionKind, error) {
	var res error
	var presentGVKs []schema.GroupVersionKind

	for _, gvk := range requiredGVKs {
		if err := checkCRD(ctx, clientset, gvk); err != nil {
			res = errors.Join(res, err)
		}
	}

	for _, optionalGVK := range optionalGVKs {
		if err := checkCRD(ctx, clientset, optionalGVK); err != nil {
			logger.DebugContext(ctx, "CRD is not present, will not handle it", logfields.OptionalGVK, optionalGVK)
			continue
		}
		// note that the .Kind field contains the _resource_ name -
		// the plural, lowercase version of the name.
		presentGVKs = append(presentGVKs, optionalGVK)
	}

	return presentGVKs, res
}

// registerReconcilers registers Gateway API reconcilers to the controller-runtime library manager.
// optionalKinds are previously autodetected based on what CRDs are present in the cluster.
func registerReconcilers(mgr ctrlRuntime.Manager, translator translation.Translator, logger *slog.Logger, installedCRDs []schema.GroupVersionKind) error {
	requiredReconcilers := []interface {
		SetupWithManager(mgr ctrlRuntime.Manager) error
	}{
		newGatewayClassReconciler(mgr, logger),
		newGatewayReconciler(mgr, translator, logger, installedCRDs),
		newGammaReconciler(mgr, translator, logger),
		newGatewayClassConfigReconciler(mgr, logger),
	}

	for _, r := range requiredReconcilers {
		if err := r.SetupWithManager(mgr); err != nil {
			return fmt.Errorf("failed to setup reconciler: %w", err)
		}
	}

	// To add a new optionalKind, remember you also need to add the GVK into
	// the optionalGVKs global.
	// Note that optionalKinds contains the lower-case, plural version of the
	// name.
	for _, gvk := range installedCRDs {
		switch gvk.Kind {
		case helpers.TLSRouteKind:
			// TLSRoute is reconciled by the Gateway API reconciler, but log that the
			// support has been successfully enabled.
			logger.Info("TLSRoute CRD is installed, TLSRoute support is enabled")
		case helpers.ServiceImportKind:
			// we don't need a reconciler, but we do need to tell folks that the
			// support is working.
			logger.Info("ServiceImport CRD is installed, ServiceImport support is enabled")
		default:
			panic(fmt.Sprintf("No reconciler available for GVK %s", gvk))
		}
	}
	return nil
}

func registerGatewayAPITypesToScheme(scheme *runtime.Scheme, optionalKinds []schema.GroupVersionKind) error {
	// Autodetection of installed types means we have to add things to the scheme
	// ourselves for non-Standard GroupVersions, we can't use the generated
	// functions.

	addToSchema := make(map[fmt.Stringer]func(s *runtime.Scheme) error)

	// We can safely install the GA resources
	addToSchema[gatewayv1.GroupVersion] = gatewayv1.AddToScheme
	// We can also safely install the v1beta1 resources, as these are legacy
	// and also included in the Standard install
	addToSchema[gatewayv1beta1.GroupVersion] = gatewayv1beta1.AddToScheme

	for _, optionalKind := range optionalKinds {
		// Note that we're using the full GVK as the map key here - this is fine
		// because the key is just a fmt.Stringer
		// We need to do this because there needs to be one entry
		//
		// Note that these calls are usually done using the package-level
		// AddToScheme, but we can't use that here because we want to only
		// enable things on a per-resource basis.
		addToSchema[optionalKind] = func(s *runtime.Scheme) error {
			s.AddKnownTypes(optionalKind.GroupVersion(), helpers.GetConcreteObject(optionalKind))
			// We also need to add the List version to the Schema
			listKind := optionalKind.Kind[:len(optionalKind.Kind)-1] + "lists"
			optionalKindList := schema.GroupVersionKind{
				Group:   optionalKind.Group,
				Version: optionalKind.Version,
				Kind:    listKind,
			}
			s.AddKnownTypes(optionalKind.GroupVersion(), helpers.GetConcreteObject(optionalKindList))
			metav1.AddToGroupVersion(s, optionalKind.GroupVersion())
			return nil
		}
	}

	for gv, f := range addToSchema {
		if err := f(scheme); err != nil {
			return fmt.Errorf("failed to add types from %s to scheme: %w", gv, err)
		}
	}

	return nil
}
