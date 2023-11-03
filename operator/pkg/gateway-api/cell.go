// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"errors"
	"fmt"

	"github.com/bombsimon/logrusr/v4"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrlRuntime "sigs.k8s.io/controller-runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging"
)

// Cell manages the Gateway API related controllers.
var Cell = cell.Module(
	"gateway-api",
	"Manages the Gateway API controllers",

	cell.Config(gatewayApiConfig{
		EnableGatewayAPISecretsSync: true,
		GatewayAPISecretsNamespace:  "cilium-secrets",
	}),
	cell.Invoke(registerController),
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

type params struct {
	cell.In

	Clientset k8sClient.Clientset
	Logger    logrus.FieldLogger
}

func registerController(lc hive.Lifecycle, p params, config gatewayApiConfig) error {
	if !operatorOption.Config.EnableGatewayAPI {
		return nil
	}

	p.Logger.WithField("requiredGVK", requiredGVK).Info("Checking for required GatewayAPI resources")
	if err := checkRequiredCRDs(context.Background(), p.Clientset); err != nil {
		p.Logger.WithError(err).Error("Required GatewayAPI resources are not found, please refer to docs for installation instructions")
		return nil
	}

	// Setting global logger for controller-runtime
	ctrlRuntime.SetLogger(logrusr.New(logging.DefaultLogger, logrusr.WithName("controller-runtime")))

	gatewayController, err := NewController(
		config.EnableGatewayAPISecretsSync,
		config.GatewayAPISecretsNamespace,
		operatorOption.Config.ProxyIdleTimeoutSeconds,
	)
	if err != nil {
		return fmt.Errorf("failed to create gateway controller: %w", err)
	}

	lc.Append(hive.Hook{
		OnStart: func(_ hive.HookContext) error {
			go gatewayController.Run()
			return nil
		},
	})

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
