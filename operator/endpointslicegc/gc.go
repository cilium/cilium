// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicegc

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_api_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// params contains all the dependencies for the endpoint-slice-gc.
// They will be provided through dependency injection.
type params struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	JobGroup  job.Group

	Clientset            k8sClient.Clientset
	CiliumEndpointSlices resource.Resource[*cilium_api_v2a1.CiliumEndpointSlice]

	SharedCfg SharedConfig
}

// GC represents the Cilium Endpoint Slice one-off GC.
type GC struct {
	logger *slog.Logger

	clientset            k8sClient.Clientset
	ciliumEndpointSlices resource.Resource[*cilium_api_v2a1.CiliumEndpointSlice]
}

func registerGC(p params) {
	if !p.Clientset.IsEnabled() {
		return
	}

	if p.SharedCfg.EnableCiliumEndpointSlice {
		return
	}

	gc := &GC{
		logger:               p.Logger,
		clientset:            p.Clientset,
		ciliumEndpointSlices: p.CiliumEndpointSlices,
	}

	p.JobGroup.Add(
		job.OneShot(
			"to-k8s-ciliumendpointslice-gc",
			gc.doGC,
			job.WithRetry(3, &job.ExponentialBackoff{
				Min: 30 * time.Second,
				Max: 120 * time.Second,
			}),
		),
	)
}

func (g *GC) checkForCiliumEndpointSliceCRD(ctx cell.HookContext) bool {
	_, err := g.clientset.ApiextensionsV1().CustomResourceDefinitions().Get(
		ctx, cilium_api_v2a1.CESName, metav1.GetOptions{ResourceVersion: "0"},
	)
	if err == nil {
		return true
	} else if k8serrors.IsNotFound(err) {
		g.logger.InfoContext(ctx, "CiliumEndpointSlice CRD cannot be found, skipping garbage collection", logfields.Error, err)
	} else {
		g.logger.ErrorContext(ctx, "Unable to determine if CiliumEndpointSlice CRD is installed, cannot start garbage collector",
			logfields.Error, err)
	}
	return false
}

func (g *GC) doGC(ctx context.Context, _ cell.Health) error {
	if !g.checkForCiliumEndpointSliceCRD(ctx) {
		// CES CRD is not present, NOT starting GC
		return nil
	}

	cesStore, err := g.ciliumEndpointSlices.Store(ctx)
	if err != nil {
		g.logger.ErrorContext(ctx, "Couldn't get CES Store", logfields.Error, err)
		return err
	}

	// For each CES we fetched, try to GC. Do not fail immediately if a CES cannot be GCed.
	var allErrors []error
	for _, ces := range cesStore.List() {
		scopedLog := g.logger.With(logfields.K8sPodName, ces.Namespace+"/"+ces.Name)

		err = g.deleteCES(ctx, ces, scopedLog)
		if err != nil {
			allErrors = append(allErrors, err)
		}
	}

	if len(allErrors) > 0 {
		return errors.Join(allErrors...)
	}
	return nil
}

func (g *GC) deleteCES(ctx context.Context, ces *cilium_api_v2a1.CiliumEndpointSlice, scopedLog *slog.Logger) error {
	ciliumClient := g.clientset.CiliumV2alpha1()
	scopedLog = scopedLog.With(logfields.CESName, ces.Name)
	propagationPolicy := metav1.DeletePropagationOrphan // because these are const strings but the API wants pointers
	err := ciliumClient.CiliumEndpointSlices().Delete(
		ctx,
		ces.Name,
		metav1.DeleteOptions{
			PropagationPolicy: &propagationPolicy,
		})
	switch {
	case err == nil:
		scopedLog.DebugContext(ctx, "CiliumEndpointSlice successfully garbage collected")
	case k8serrors.IsNotFound(err), k8serrors.IsConflict(err):
		scopedLog.DebugContext(ctx, "Unable to delete CiliumEndpointSlice", logfields.Error, err)
	default:
		scopedLog.WarnContext(ctx, "Unable to delete orphaned CiliumEndpointSlice", logfields.Error, err)
		return err
	}
	return nil
}
