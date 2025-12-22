// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"github.com/cilium/hive/cell"
	corev1 "k8s.io/api/core/v1"
	resourceapi "k8s.io/api/resource/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/util/workqueue"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/utils"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/promise"
)

func resourceClaimResource(
	lc cell.Lifecycle,
	cs k8sClient.Clientset,
	mp workqueue.MetricsProvider,
	crdSync promise.Promise[synced.CRDSync],
) (resource.Resource[*resourceapi.ResourceClaim], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(utils.ListerWatcherFromTyped(cs.ResourceV1().ResourceClaims("")))
	return resource.New[*resourceapi.ResourceClaim](
		lc, lw, mp,
		resource.WithMetric("ResourceClaim"),
		resource.WithCRDSync(crdSync),
	), nil
}

func podResource(
	lc cell.Lifecycle,
	cs k8sClient.Clientset,
	mp workqueue.MetricsProvider,
	crdSync promise.Promise[synced.CRDSync],
) (resource.Resource[*corev1.Pod], error) {
	if !cs.IsEnabled() {
		return nil, nil
	}
	lw := utils.ListerWatcherWithModifiers(
		utils.ListerWatcherFromTyped(cs.CoreV1().Pods("")),
		func(opts *metav1.ListOptions) {
			opts.FieldSelector = fields.ParseSelectorOrDie("spec.nodeName=" + nodetypes.GetName()).String()
		},
	)
	return resource.New[*corev1.Pod](lc, lw, mp,
		resource.WithMetric("Pod"),
		resource.WithCRDSync(crdSync),
	), nil
}
