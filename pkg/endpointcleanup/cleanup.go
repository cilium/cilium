// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointcleanup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointstate"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/resiliency"
	"github.com/cilium/cilium/pkg/time"
)

type localEndpointCache interface {
	LookupCEPName(namespacedName string) *endpoint.Endpoint
}

type params struct {
	cell.In

	Logger              *slog.Logger
	Lifecycle           cell.Lifecycle
	JobGroup            job.Group
	Health              cell.Health
	CiliumEndpoint      resource.Resource[*types.CiliumEndpoint]
	CiliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	Clientset           k8sClient.Clientset
	RestorerPromise     promise.Promise[endpointstate.Restorer]
	EndpointsCache      localEndpointCache
	Cfg                 Config
	DaemonCfg           *option.DaemonConfig
}

type cleanup struct {
	log                        *slog.Logger
	ciliumEndpoint             resource.Resource[*types.CiliumEndpoint]
	ciliumEndpointSlice        resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	ciliumClient               cilium_v2.CiliumV2Interface
	restorerPromise            promise.Promise[endpointstate.Restorer]
	endpointsCache             localEndpointCache
	ciliumEndpointSliceEnabled bool
}

func registerCleanup(p params) {
	if !p.Clientset.IsEnabled() || !p.Cfg.EnableStaleCiliumEndpointCleanup || p.DaemonCfg.DisableCiliumEndpointCRD ||
		// When Cilium is configured in KVstore mode, we don't start the CiliumEndpoints informer
		// at all. Hence, let's disable this GC logic as well, given that it would otherwise
		// need to start it to populate the store content. Indeed, no one is expected to be
		// watching them, and we can accept the possibility that we leak a few objects in
		// very specific and rare circumstances [1], until the corresponding pod gets deleted.
		// The respective kvstore entries, which are not taken into account here, will be
		// instead eventually deleted when the corresponding lease expires.
		//
		// [1]: cilium/cilium#20350
		p.DaemonCfg.KVstoreEnabled() {
		p.Logger.Info("Init procedure to clean up stale CiliumEndpoint disabled")
		return
	}

	cleanup := &cleanup{
		log:                        p.Logger,
		ciliumEndpoint:             p.CiliumEndpoint,
		ciliumEndpointSlice:        p.CiliumEndpointSlice,
		ciliumClient:               p.Clientset.CiliumV2(),
		restorerPromise:            p.RestorerPromise,
		endpointsCache:             p.EndpointsCache,
		ciliumEndpointSliceEnabled: p.DaemonCfg.EnableCiliumEndpointSlice,
	}

	p.JobGroup.Add(
		job.OneShot("endpoint-cleanup", func(ctx context.Context, health cell.Health) error {
			return cleanup.run(ctx)
		}),
	)
}

func (c *cleanup) run(ctx context.Context) error {
	// Use restored endpoints to delete local CiliumEndpoints which are not in the restored endpoint cache.
	// This will clear out any CiliumEndpoints that may be stale.
	// Likely causes for this are Pods having their init container restarted or the node being restarted.
	// This must wait for both K8s watcher caches to be synced and local endpoint restoration to be complete.
	// Note: Synchronization of endpoints to their CEPs may not be complete at this point, but we only have to
	// know what endpoints exist post-restoration in our endpointManager cache to perform cleanup.
	restorer, err := c.restorerPromise.Await(ctx)
	if err != nil {
		return err
	}
	restorer.WaitForEndpointRestore(ctx)

	var (
		retries int
		bo      = wait.Backoff{
			Duration: 500 * time.Millisecond,
			Factor:   1,
			Jitter:   0.1,
			Steps:    5,
			Cap:      0,
		}
	)
	err = wait.ExponentialBackoffWithContext(ctx, bo, func(ctx context.Context) (done bool, err error) {
		if c.ciliumEndpointSliceEnabled {
			err = c.cleanStaleCESs(ctx)
		} else {
			err = c.cleanStaleCEPs(ctx)
		}
		if err != nil {
			retries++
			c.log.Error(
				"Failed to clean up stale CEPs",
				logfields.Error, err,
				logfields.Attempt, retries,
			)
			if resiliency.IsRetryable(err) {
				return false, nil
			}
			return true, err
		}
		return true, nil
	})
	if err != nil {
		c.log.Error("Failed to clean up stale CEPs after multiple attempts", logfields.Error, err)
	}
	return err
}

func (c *cleanup) cleanStaleCEPs(ctx context.Context) error {
	var errs error
	store, err := c.ciliumEndpoint.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to get CiliumEndpoint store: %w", err)
	}
	objs, err := store.ByIndex("localNode", node.GetCiliumEndpointNodeIP(c.log))
	if err != nil {
		return fmt.Errorf("failed to get indexed CiliumEndpointSlice from store: %w", err)
	}
	for _, cep := range objs {
		if cep.Networking.NodeIP == node.GetCiliumEndpointNodeIP(c.log) && c.endpointsCache.LookupCEPName(cep.Namespace+"/"+cep.Name) == nil {
			if err := c.deleteCiliumEndpoint(ctx, cep.Namespace, cep.Name, &cep.ObjectMeta.UID); err != nil {
				errs = errors.Join(errs, err)
			}
		}
	}
	return errs
}

func (c *cleanup) cleanStaleCESs(ctx context.Context) error {
	var errs error
	store, err := c.ciliumEndpointSlice.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to get CiliumEndpointSlice store: %w", err)
	}
	objs, err := store.ByIndex("localNode", node.GetCiliumEndpointNodeIP(c.log))
	if err != nil {
		return fmt.Errorf("failed to get indexed CiliumEndpointSlice from store: %w", err)
	}
	for _, ces := range objs {
		for _, cep := range ces.Endpoints {
			if cep.Networking.NodeIP == node.GetCiliumEndpointNodeIP(c.log) && c.endpointsCache.LookupCEPName(ces.Namespace+"/"+cep.Name) == nil {
				if err := c.deleteCiliumEndpoint(ctx, ces.Namespace, cep.Name, nil); err != nil {
					errs = errors.Join(errs, err)
				}
			}
		}
	}
	return errs
}

// deleteCiliumEndpoint safely deletes a CEP by name, if no UID is passed this will reverify that
// the CEP is still local before doing a delete.
func (c *cleanup) deleteCiliumEndpoint(ctx context.Context, cepNamespace, cepName string, cepUID *apiTypes.UID) error {
	scopedLogger := c.log.With(
		logfields.CEPName, cepName,
		logfields.K8sNamespace, cepNamespace,
	)

	// To avoid having to store CEP UIDs in CES Endpoints array, we have to get the latest
	// referenced CEP from apiserver to verify that it still references this node.
	// To avoid excessive api calls, we only do this if CES is enabled and the CEP
	// appears to be stale.
	if cepUID == nil && c.ciliumEndpointSliceEnabled {
		cep, err := c.ciliumClient.CiliumEndpoints(cepNamespace).Get(ctx, cepName, metav1.GetOptions{})
		if err != nil {
			if k8serrors.IsNotFound(err) {
				scopedLogger.Info(
					"CEP no longer exists, skipping staleness check",
					logfields.Error, err,
				)
				return nil
			}
			scopedLogger.Error(
				"Failed to get possibly stale ciliumendpoints from apiserver",
			)
			return resiliency.Retryable(err)
		}
		if cep.Status.Networking.NodeIP != node.GetCiliumEndpointNodeIP(c.log) {
			scopedLogger.Debug(
				"Stale CEP fetched apiserver no longer references this Node, skipping.",
				logfields.Error, err,
			)
			return nil
		}
		cepUID = &cep.ObjectMeta.UID
	}
	// There exists a local CiliumEndpoint that is not in the endpoint manager.
	// This function is run after completing endpoint restoration from local state and K8s cache sync.
	// Therefore, we can delete the CiliumEndpoint as it is not referencing a Pod that is being managed.
	// This may occur for various reasons:
	// * Pod was restarted while Cilium was not running (likely prior to CNI conf being installed).
	// * Local endpoint was deleted (i.e. due to reboot + temporary filesystem) and Cilium or the Pod where restarted.
	scopedLogger.Info(
		"Found stale ciliumendpoint for local pod that is not being managed, deleting.",
	)
	if err := c.ciliumClient.CiliumEndpoints(cepNamespace).Delete(ctx, cepName, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{
			UID: cepUID,
		},
	}); err != nil {
		if k8serrors.IsNotFound(err) {
			// CEP not found, likely already deleted. Do not log as an error as that
			// will fail CI runs.
			scopedLogger.Debug(
				"Could not delete stale CEP",
			)
			return nil
		}
		scopedLogger.Error(
			"Could not delete stale CEP",
		)
		return resiliency.Retryable(err)
	}

	return nil
}
