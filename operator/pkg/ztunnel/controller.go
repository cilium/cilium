// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ztunnel

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"

	operatorOption "github.com/cilium/cilium/operator/option"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	ztunnelDaemonSetName = "ztunnel-cilium"
)

// controller manages a ztunnel daemonset, ensuring a ztunnel proxy runs on each
// node in the cluster.
type controller struct {
	client         k8sClient.Clientset
	logger         *slog.Logger
	config         Config
	operatorConfig *operatorOption.OperatorConfig
}

// create will create the ztunnel daemonset.
func (c *controller) create(ctx context.Context, ds *appsv1.DaemonSet, ns string) error {
	_, err := c.client.AppsV1().DaemonSets(ns).Create(ctx, ds, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create ztunnel DaemonSet: %w", err)
	}

	c.logger.Info("Successfully created ztunnel DaemonSet")
	return nil
}

// createIfNotExists ensures the ztunnel DaemonSet exists and creates it if it doesn't
func (c *controller) createIfNotExists(ctx context.Context, ds *appsv1.DaemonSet, ns string) error {
	// Check if DaemonSet already exists
	_, err := c.client.AppsV1().DaemonSets(ns).Get(ctx, ztunnelDaemonSetName, metav1.GetOptions{})
	if err == nil {
		return nil
	}

	if !errors.IsNotFound(err) {
		return fmt.Errorf("failed to get ztunnel DaemonSet: %w", err)
	}

	return c.create(ctx, ds, ns)
}

// remove removes the ztunnel DaemonSet if it exists
func (c *controller) remove(ctx context.Context, ns string) error {
	// Check if DaemonSet exists
	_, err := c.client.AppsV1().DaemonSets(ns).Get(ctx, ztunnelDaemonSetName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		// DaemonSet doesn't exist, nothing to clean up
		c.logger.Debug("ztunnel DaemonSet not found, nothing to clean up")
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to get ztunnel DaemonSet: %w", err)
	}

	// DaemonSet exists, delete it
	err = c.client.AppsV1().DaemonSets(ns).Delete(ctx, ztunnelDaemonSetName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete ztunnel DaemonSet: %w", err)
	}

	c.logger.Info("Successfully deleted ztunnel DaemonSet")
	return nil
}

// run will launch a background reconciler for a ztunnel daemonset.
//
// if ztunnel is not enabled in the configuration any stale ztunnel daemonset
// will be removed.
//
// if ztunnel is enabled an Informer which watches for deleted daemonsets will
// be spawned.
// if we detect a delete event for the ztunnel daemonset, we will recreate it.
//
// after the controller is launched we will ensure that the ztunnel daemonset
// exists, creating it if it does not.
func (c *controller) run(ctx context.Context, ds *appsv1.DaemonSet) error {
	// we must know Cilium's namespace
	if c.operatorConfig.CiliumK8sNamespace == "" {
		return fmt.Errorf("cannot run ztunnel controller: CiliumK8sNamespace is not set")
	}

	// ztunnel may have been enabled, disabled, and the operator has restarted.
	// therefore, cleanup stale ztunnel daemonset.
	if !c.config.EnableZTunnel {
		c.logger.Info("ztunnel encryption disabled, cleaning up DaemonSet if it exists")
		return c.remove(ctx, c.operatorConfig.CiliumK8sNamespace)
	}

	// Set up watcher for DaemonSet events, if we catch a delete of the ztunnel
	// daemonset, we will recreate it.
	listWatcher := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return c.client.AppsV1().DaemonSets(c.operatorConfig.CiliumK8sNamespace).List(ctx, metav1.ListOptions{
				FieldSelector: fields.OneTermEqualSelector("metadata.name", ztunnelDaemonSetName).String(),
			})
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return c.client.AppsV1().DaemonSets(c.operatorConfig.CiliumK8sNamespace).Watch(ctx, metav1.ListOptions{
				FieldSelector: fields.OneTermEqualSelector("metadata.name", ztunnelDaemonSetName).String(),
			})
		},
	}

	_, controller := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: listWatcher,
		ObjectType:    &appsv1.DaemonSet{},
		ResyncPeriod:  time.Minute * 5,
		Handler: cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(oldObj, newObj any) {
				oldDS, ok := oldObj.(*appsv1.DaemonSet)
				if !ok {
					return
				}
				newDS, ok := newObj.(*appsv1.DaemonSet)
				if !ok {
					return
				}

				// Only care about spec changes, not status
				if oldDS.Generation == newDS.Generation {
					return
				}

				c.logger.Warn("ztunnel DaemonSet spec modified externally and changes may be overwritten on operator restart")
			},
			DeleteFunc: func(obj any) {
				// Check if the deleted object is our ztunnel DaemonSet
				deletedDS, ok := obj.(*appsv1.DaemonSet)
				if !ok {
					tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
					if ok {
						deletedDS, ok = tombstone.Obj.(*appsv1.DaemonSet)
					}
					if !ok {
						c.logger.Debug("Received non-DaemonSet delete event")
						return
					}
				}

				if deletedDS.Name != ztunnelDaemonSetName || deletedDS.Namespace != c.operatorConfig.CiliumK8sNamespace {
					c.logger.Debug(
						"Deleted DaemonSet is not our ztunnel DaemonSet",
						logfields.Name,
						deletedDS.Name,
						logfields.K8sNamespace,
						deletedDS.Namespace)
					return
				}

				// Our ztunnel DaemonSet was deleted, recreate it with createIfNotExists,
				// just incase this is an out-of-order event and the daemonset was already
				// recreated.
				c.logger.Info("ztunnel DaemonSet was deleted, recreating...")
				if err := c.createIfNotExists(ctx, ds, c.operatorConfig.CiliumK8sNamespace); err != nil {
					c.logger.Error(
						"Error recreating ztunnel DaemonSet after deletion", logfields.Error, err)
				}
			},
		},
	})

	// Start the controller
	go controller.RunWithContext(ctx)

	// Initial reconciliation - ensure DaemonSet exists
	if err := c.createIfNotExists(ctx, ds, c.operatorConfig.CiliumK8sNamespace); err != nil {
		return fmt.Errorf("failed initial DaemonSet reconciliation: %w", err)
	}

	return nil
}
