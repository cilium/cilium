// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"fmt"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// TranslationExtension modifies the translated Envoy configuration before it
// is persisted. Implementations must not persist the configuration themselves.
type TranslationExtension interface {
	// Name returns the stable extension name used in diagnostics.
	Name() string

	// Enabled reports whether the extension should be applied.
	Enabled() bool

	// Apply modifies cec for gateway. The extension may defer reconciliation to
	// preserve the last successfully applied configuration.
	Apply(context.Context, *gatewayv1.Gateway, *ciliumv2.CiliumEnvoyConfig) (TranslationExtensionResult, error)
}

// TranslationExtensionResult controls Gateway reconciliation after an
// extension has been applied.
type TranslationExtensionResult struct {
	DeferReconcile bool
}

func (r *gatewayReconciler) applyTranslationExtensions(
	ctx context.Context,
	gateway *gatewayv1.Gateway,
	cec *ciliumv2.CiliumEnvoyConfig,
) (bool, error) {
	if cec == nil {
		return false, nil
	}

	for _, extension := range r.translationExtensions {
		if !extension.Enabled() {
			continue
		}

		result, err := extension.Apply(ctx, gateway, cec)
		if err != nil {
			return false, fmt.Errorf("translation extension %q failed: %w", extension.Name(), err)
		}

		if result.DeferReconcile {
			return true, nil
		}
	}

	return false, nil
}
