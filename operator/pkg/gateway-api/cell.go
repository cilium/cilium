// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlRuntime "sigs.k8s.io/controller-runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
)

// Cell manages the Gateway API related controllers.
var Cell = cell.Module(
	"gateway-api",
	"Manages the Gateway API controllers",

	cell.Config(gatewayApiConfig{
		EnableGatewayAPISecretsSync: true,
		GatewayAPISecretsNamespace:  "cilium-secrets",
	}),
	cell.Invoke(initGatewayAPIController),
)

var requiredGVK = []schema.GroupVersionKind{
	gatewayv1.SchemeGroupVersion.WithKind("gatewayclasses"),
	gatewayv1.SchemeGroupVersion.WithKind("gateways"),
	gatewayv1.SchemeGroupVersion.WithKind("httproutes"),
	gatewayv1beta1.SchemeGroupVersion.WithKind("referencegrants"),
	gatewayv1alpha2.SchemeGroupVersion.WithKind("grpcroutes"),
	gatewayv1alpha2.SchemeGroupVersion.WithKind("tlsroutes"),
}

type gatewayApiConfig struct {
	EnableGatewayAPISecretsSync bool
	GatewayAPISecretsNamespace  string
}

func (r gatewayApiConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-gateway-api-secrets-sync", r.EnableGatewayAPISecretsSync, "Enables fan-in TLS secrets sync from multiple namespaces to singular namespace (specified by gateway-api-secrets-namespace flag)")
	flags.String("gateway-api-secrets-namespace", r.GatewayAPISecretsNamespace, "Namespace having tls secrets used by CEC for Gateway API")
}

type gatewayAPIParams struct {
	cell.In

	Logger    logrus.FieldLogger
	Lifecycle hive.Lifecycle

	K8sClient          client.Clientset
	CtrlRuntimeManager ctrlRuntime.Manager
	Scheme             *runtime.Scheme

	Config gatewayApiConfig
}

func initGatewayAPIController(params gatewayAPIParams) error {
	if !operatorOption.Config.EnableGatewayAPI {
		return nil
	}

	params.Logger.WithField("requiredGVK", requiredGVK).Info("Checking for required GatewayAPI resources")
	if err := checkRequiredCRDs(context.Background(), params.K8sClient); err != nil {
		params.Logger.WithError(err).Error("Required GatewayAPI resources are not found, please refer to docs for installation instructions")
		return nil
	}

	if err := registerGatewayAPITypesToScheme(params.Scheme); err != nil {
		return err
	}

	if err := registerReconcilers(
		params.CtrlRuntimeManager,
		params.Config.EnableGatewayAPISecretsSync,
		params.Config.GatewayAPISecretsNamespace,
		operatorOption.Config.ProxyIdleTimeoutSeconds,
	); err != nil {
		return fmt.Errorf("failed to create gateway controller: %w", err)
	}

	return nil
}

func checkRequiredCRDs(ctx context.Context, clientset k8sClient.Clientset) error {
	if !clientset.IsEnabled() {
		return nil
	}

	var res error

	for _, gvk := range requiredGVK {
		crd, err := clientset.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, gvk.GroupKind().String(), metav1.GetOptions{})
		if err != nil {
			res = errors.Join(res, err)
			continue
		}

		found := false
		for _, v := range crd.Spec.Versions {
			if v.Name == gvk.Version {
				found = true
				break
			}
		}
		if !found {
			res = errors.Join(res, fmt.Errorf("CRD %q does not have version %q", gvk.GroupKind().String(), gvk.Version))
		}
	}

	return res
}

// registerReconcilers registers the Gateway API reconcilers to the controller-runtime library manager.
func registerReconcilers(mgr ctrlRuntime.Manager, enableSecretSync bool, secretsNamespace string, idleTimeoutSeconds int) error {
	reconcilers := []interface {
		SetupWithManager(mgr ctrlRuntime.Manager) error
	}{
		newGatewayClassReconciler(mgr),
		newGatewayReconciler(mgr, secretsNamespace, idleTimeoutSeconds),
		newReferenceGrantReconciler(mgr),
		newHTTPRouteReconciler(mgr),
		newGRPCRouteReconciler(mgr),
		newTLSRouteReconciler(mgr),
	}

	if enableSecretSync {
		reconcilers = append(reconcilers, newSecretSyncReconciler(mgr, log, &gatewayv1.Gateway{}, enqueueTLSSecrets(mgr.GetClient()), secretsNamespace))
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
