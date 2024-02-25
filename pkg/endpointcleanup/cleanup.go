// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointcleanup

import (
	"context"
	"errors"
	"fmt"
	"runtime/pprof"

	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
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

	Logger              logrus.FieldLogger
	Lifecycle           cell.Lifecycle
	JobRegistry         job.Registry
	Scope               cell.Scope
	CiliumEndpoint      resource.Resource[*types.CiliumEndpoint]
	CiliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	Clientset           k8sClient.Clientset
	RestorerPromise     promise.Promise[endpointstate.Restorer]
	EndpointsCache      localEndpointCache
	Cfg                 Config
	DaemonCfg           *option.DaemonConfig
}

type cleanup struct {
	log                        logrus.FieldLogger
	ciliumEndpoint             resource.Resource[*types.CiliumEndpoint]
	ciliumEndpointSlice        resource.Resource[*cilium_v2a1.CiliumEndpointSlice]
	ciliumClient               cilium_v2.CiliumV2Interface
	restorerPromise            promise.Promise[endpointstate.Restorer]
	endpointsCache             localEndpointCache
	ciliumEndpointSliceEnabled bool
	storeReleaseFn             func()
}

func registerCleanup(p params) {
	if !p.Clientset.IsEnabled() || !p.Cfg.EnableStaleCiliumEndpointCleanup || p.DaemonCfg.DisableCiliumEndpointCRD {
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

	jobGroup := p.JobRegistry.NewGroup(
		p.Scope,
		job.WithLogger(p.Logger),
		job.WithPprofLabels(pprof.Labels("cell", "endpoint-cleanup")),
	)

	jobGroup.Add(
		job.OneShot("endpoint-cleanup", func(ctx context.Context, health cell.HealthReporter) error {
			return cleanup.run(ctx)
		}),
	)

	p.Lifecycle.Append(jobGroup)
}

func (c *cleanup) run(ctx context.Context) error {
	defer func() {
		if c.storeReleaseFn != nil {
			c.storeReleaseFn()
		}
	}()

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
			c.log.WithError(err).WithField(logfields.Attempt, retries).Error("Failed to clean up stale CEPs")
			if resiliency.IsRetryable(err) {
				return false, nil
			}
			return true, err
		}
		return true, nil
	})
	if err != nil {
		c.log.WithError(err).Error("Failed to clean up stale CEPs after multiple attempts")
	}
	return err
}

func (c *cleanup) cleanStaleCEPs(ctx context.Context) error {
	var errs error
	store, err := c.ciliumEndpoint.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to get CiliumEndpoint store: %w", err)
	}
	c.storeReleaseFn = store.Release
	objs, err := store.ByIndex("localNode", node.GetCiliumEndpointNodeIP())
	if err != nil {
		return fmt.Errorf("failed to get indexed CiliumEndpointSlice from store: %w", err)
	}
	for _, cep := range objs {
		if cep.Networking.NodeIP == node.GetCiliumEndpointNodeIP() && c.endpointsCache.LookupCEPName(cep.Namespace+"/"+cep.Name) == nil {
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
	c.storeReleaseFn = store.Release
	objs, err := store.ByIndex("localNode", node.GetCiliumEndpointNodeIP())
	if err != nil {
		return fmt.Errorf("failed to get indexed CiliumEndpointSlice from store: %w", err)
	}
	for _, ces := range objs {
		for _, cep := range ces.Endpoints {
			if cep.Networking.NodeIP == node.GetCiliumEndpointNodeIP() && c.endpointsCache.LookupCEPName(ces.Namespace+"/"+cep.Name) == nil {
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
	logwf := c.log.WithFields(logrus.Fields{
		logfields.CEPName:      cepName,
		logfields.K8sNamespace: cepNamespace,
	})

	// To avoid having to store CEP UIDs in CES Endpoints array, we have to get the latest
	// referenced CEP from apiserver to verify that it still references this node.
	// To avoid excessive api calls, we only do this if CES is enabled and the CEP
	// appears to be stale.
	if cepUID == nil && c.ciliumEndpointSliceEnabled {
		cep, err := c.ciliumClient.CiliumEndpoints(cepNamespace).Get(ctx, cepName, metav1.GetOptions{})
		if err != nil {
			if k8serrors.IsNotFound(err) {
				logwf.WithError(err).Info("CEP no longer exists, skipping staleness check")
				return nil
			}
			logwf.WithError(err).Error("Failed to get possibly stale ciliumendpoints from apiserver")
			return resiliency.Retryable(err)
		}
		if cep.Status.Networking.NodeIP != node.GetCiliumEndpointNodeIP() {
			logwf.WithError(err).Debug("Stale CEP fetched apiserver no longer references this Node, skipping.")
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
	logwf.Info("Found stale ciliumendpoint for local pod that is not being managed, deleting.")
	if err := c.ciliumClient.CiliumEndpoints(cepNamespace).Delete(ctx, cepName, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{
			UID: cepUID,
		},
	}); err != nil {
		if k8serrors.IsNotFound(err) {
			// CEP not found, likely already deleted. Do not log as an error as that
			// will fail CI runs.
			logwf.Debug("Could not delete stale CEP")
			return nil
		}
		logwf.Error("Could not delete stale CEP")
		return resiliency.Retryable(err)
	}

	return nil
}
