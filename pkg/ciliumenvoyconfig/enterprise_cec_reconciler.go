// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Isovalent

package ciliumenvoyconfig

import (
	"context"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/endpoint"
	pkgLabels "github.com/cilium/cilium/pkg/labels"
)

func (r *ciliumEnvoyConfigReconciler) ensureIngressEndpoint(ctx context.Context, meta metav1.ObjectMeta) (*endpoint.Endpoint, error) {
	var extraLabels = pkgLabels.Labels{}

	for k, v := range meta.Labels {
		extraLabels[k] = pkgLabels.NewLabel(k, v, pkgLabels.LabelSourceK8s)
	}

	if len(meta.GetNamespace()) != 0 {
		extraLabels["io.kubernetes.pod.namespace"] = pkgLabels.NewLabel("io.kubernetes.pod.namespace", "default", pkgLabels.LabelSourceK8s)
	}

	return r.ingressEndpoint.ensureIngressEndpoint(ctx, meta.GetName(), extraLabels)
}
