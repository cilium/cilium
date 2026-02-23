// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicegc

import (
	"context"
	"log/slog"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ces "github.com/cilium/cilium/operator/pkg/ciliumendpointslice"
	cilium_api_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// params contains all the dependencies for the endpoint-slice-gc.
// They will be provided through dependency injection.
type params struct {
	cell.In

	Logger   *slog.Logger
	JobGroup job.Group

	Clientset k8sClient.Clientset

	SharedCfg ces.SharedConfig
}

// GC represents the Cilium Endpoint Slice one-off GC.
type GC struct {
	logger *slog.Logger

	clientset k8sClient.Clientset
}

func registerGC(p params) {
	if !p.Clientset.IsEnabled() {
		return
	}

	if p.SharedCfg.EnableCiliumEndpointSlice {
		return
	}

	gc := &GC{
		logger:    p.Logger,
		clientset: p.Clientset,
	}

	p.JobGroup.Add(
		job.OneShot(
			"to-k8s-ciliumendpointslice-gc",
			gc.doGC,
			job.WithRetry(3, &job.ExponentialBackoff{
				Min: 1 * time.Minute,
				Max: 5 * time.Minute,
			}),
		),
	)
}

// Return whether the CiliumEndpointSlice CRD exists and the error encountered in
// checking for its existence, if any.
func (g *GC) checkForCiliumEndpointSliceCRD(ctx context.Context) (bool, error) {
	_, err := g.clientset.ApiextensionsV1().CustomResourceDefinitions().Get(
		ctx, cilium_api_v2a1.CESName, metav1.GetOptions{ResourceVersion: "0"},
	)
	if err == nil {
		return true, nil
	} else if k8serrors.IsNotFound(err) {
		g.logger.InfoContext(ctx, "CiliumEndpointSlice CRD cannot be found, skipping garbage collection", logfields.Error, err)
		return false, nil
	} else {
		// Some APIServer error occurred, return error so we can retry
		g.logger.ErrorContext(ctx, "Unable to determine if CiliumEndpointSlice CRD is installed, cannot start garbage collector",
			logfields.Error, err)
		return false, err
	}
}

func (g *GC) doGC(ctx context.Context, _ cell.Health) error {
	if ok, err := g.checkForCiliumEndpointSliceCRD(ctx); !ok {
		// CES CRD is not present, NOT starting GC
		return err
	}

	// CES have no dependent resources; when CES are disabled and being GCed,
	// they should not be treated as an owner.
	propagationPolicy := metav1.DeletePropagationOrphan
	err := g.clientset.CiliumV2alpha1().CiliumEndpointSlices().DeleteCollection(
		ctx,
		metav1.DeleteOptions{
			PropagationPolicy: &propagationPolicy,
		},
		metav1.ListOptions{},
	)
	return err
}
