// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/hive/cell"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
)

type QueuedItem interface {
	Key() resource.Key
}
type queueOperations interface {
	enqueueReconciliation(item QueuedItem, delay time.Duration)
}

type params struct {
	cell.In

	Logger              *slog.Logger
	Lifecycle           cell.Lifecycle
	Clientset           k8sClient.Clientset
	SharedCfg           SharedConfig
	Namespace           resource.Resource[*slim_corev1.Namespace]
	Pod                 resource.Resource[*slim_corev1.Pod]
	CiliumIdentity      resource.Resource[*cilium_api_v2.CiliumIdentity]
	CiliumEndpoint      resource.Resource[*cilium_api_v2.CiliumEndpoint]
	CiliumEndpointSlice resource.Resource[*v2alpha1.CiliumEndpointSlice]
}

type Controller struct {
	logger              *slog.Logger
	context             context.Context
	contextCancel       context.CancelFunc
	clientset           k8sClient.Clientset
	reconciler          *reconciler
	namespace           resource.Resource[*slim_corev1.Namespace]
	pod                 resource.Resource[*slim_corev1.Pod]
	ciliumIdentity      resource.Resource[*cilium_api_v2.CiliumIdentity]
	ciliumEndpoint      resource.Resource[*cilium_api_v2.CiliumEndpoint]
	ciliumEndpointSlice resource.Resource[*v2alpha1.CiliumEndpointSlice]

	cesEnabled bool

	// oldNSSecurityLabels is a map between namespace, and it's security labels.
	// It's used to track previous state of labels, to detect when labels changed.
	oldNSSecurityLabels map[string]labels.Labels
}

func registerController(p params) {
	if !p.Clientset.IsEnabled() || !p.SharedCfg.EnableOperatorManageCIDs {
		return
	}

	cidController := &Controller{
		logger:              p.Logger,
		clientset:           p.Clientset,
		namespace:           p.Namespace,
		pod:                 p.Pod,
		ciliumIdentity:      p.CiliumIdentity,
		ciliumEndpoint:      p.CiliumEndpoint,
		ciliumEndpointSlice: p.CiliumEndpointSlice,
		oldNSSecurityLabels: make(map[string]labels.Labels),
		cesEnabled:          p.SharedCfg.EnableCiliumEndpointSlice,
	}

	p.Lifecycle.Append(cidController)
}

func (c *Controller) Start(_ cell.HookContext) error {
	c.logger.Info("Starting CID controller Operator")
	defer utilruntime.HandleCrash()

	var err error
	c.context, c.contextCancel = context.WithCancel(context.Background())
	c.reconciler, err = newReconciler(
		c.context,
		c.logger,
		c.clientset,
		c.namespace,
		c.pod,
		c.ciliumIdentity,
		c.ciliumEndpoint,
		c.ciliumEndpointSlice,
		c.cesEnabled,
		c,
	)

	if err != nil {
		return fmt.Errorf("cid reconciler failed to init: %w", err)
	}

	c.logger.Info("Starting CID controller reconciler")

	// The desired state needs to be calculated before the events are processed.
	if err := c.reconciler.calcDesiredStateOnStartup(); err != nil {
		return fmt.Errorf("cid controller failed to calculate the desired state: %w", err)
	}

	return nil
}

func (c *Controller) enqueueReconciliation(item QueuedItem, delay time.Duration) {
}

func (c *Controller) Stop(hookContext cell.HookContext) error {
	return nil
}
