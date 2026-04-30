// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package predicates

import (
	"context"
	"log/slog"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

func SecretUsedInGatewayFn(c client.Client, logger *slog.Logger) func(obj client.Object) bool {
	return func(obj client.Object) bool {
		return len(helpers.GetGatewaysForSecret(context.Background(), c, obj, logger)) > 0
	}
}
