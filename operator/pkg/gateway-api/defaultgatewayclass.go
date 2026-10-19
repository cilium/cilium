// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	defaultGatewayClassName        = "cilium"
	defaultGatewayClassDescription = "The default Cilium GatewayClass"
)

// newDefaultGatewayClass returns the default Cilium GatewayClass, matching
// the one created by the Helm chart. If helmRelease ("<namespace>/<name>") is
// set, the GatewayClass carries the Helm ownership metadata, so that Helm
// adopts it once the Gateway API CRDs are present when rendering the chart.
func newDefaultGatewayClass(helmRelease string) (*gatewayv1.GatewayClass, error) {
	gwc := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: defaultGatewayClassName},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: defaultControllerName,
			Description:    ptr.To(defaultGatewayClassDescription),
		},
	}

	if helmRelease != "" {
		namespace, name, ok := strings.Cut(helmRelease, "/")
		if !ok || namespace == "" || name == "" {
			return nil, fmt.Errorf("invalid Helm release %q, expected <namespace>/<name>", helmRelease)
		}
		gwc.Labels = map[string]string{"app.kubernetes.io/managed-by": "Helm"}
		gwc.Annotations = map[string]string{
			"meta.helm.sh/release-name":      name,
			"meta.helm.sh/release-namespace": namespace,
		}
	}
	return gwc, nil
}

// createDefaultGatewayClass creates the default Cilium GatewayClass if it
// doesn't exist yet. This is required when the Gateway API CRDs are installed
// by the operator, as Helm cannot create the GatewayClass before its CRD
// exists. An existing GatewayClass is never modified, nor deleted.
func createDefaultGatewayClass(ctx context.Context, logger *slog.Logger, c client.Writer, helmRelease string) error {
	gwc, err := newDefaultGatewayClass(helmRelease)
	if err != nil {
		return err
	}

	switch err := c.Create(ctx, gwc); {
	case k8serrors.IsAlreadyExists(err):
		logger.Debug("Default GatewayClass already exists, not modifying it", logfields.Name, gwc.Name)
	case err != nil:
		return fmt.Errorf("unable to create the default GatewayClass %s: %w", gwc.Name, err)
	default:
		logger.Info("Created the default GatewayClass", logfields.Name, gwc.Name)
	}
	return nil
}
