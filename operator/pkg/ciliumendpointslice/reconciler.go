// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// reconciler is used to sync the current (i.e. desired) state of the CESs in datastore into current state CESs in the k8s-apiserver.
// The source of truth is in local datastore.
type reconciler struct {
	logger     *slog.Logger
	client     clientset.CiliumV2alpha1Interface
	context    context.Context
	cesManager operations
	cepStore   resource.Store[*cilium_v2.CiliumEndpoint]
	cesStore   resource.Store[*cilium_v2a1.CiliumEndpointSlice]
	metrics    *Metrics
}

// newReconciler creates and initializes a new reconciler.
func newReconciler(
	ctx context.Context,
	client clientset.CiliumV2alpha1Interface,
	cesMgr operations,
	logger *slog.Logger,
	ciliumEndpoint resource.Resource[*cilium_v2.CiliumEndpoint],
	ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
	metrics *Metrics,
) *reconciler {
	cepStore, _ := ciliumEndpoint.Store(ctx)
	cesStore, _ := ciliumEndpointSlice.Store(ctx)
	return &reconciler{
		context:    ctx,
		logger:     logger,
		client:     client,
		cesManager: cesMgr,
		cepStore:   cepStore,
		cesStore:   cesStore,
		metrics:    metrics,
	}
}

func (r *reconciler) reconcileCES(cesName CESName) (err error) {
	desiredCEPsNumber := r.cesManager.getCEPCountInCES(cesName)
	r.metrics.CiliumEndpointSliceDensity.Observe(float64(desiredCEPsNumber))
	// Check the CES exists is in cesStore i.e. in api-server copy of CESs, if exist update or delete the CES.
	cesObj, exists, err := r.cesStore.GetByKey(NewCESKey(cesName.string(), "").key())
	if err != nil {
		return
	}
	if !exists && desiredCEPsNumber > 0 {
		return r.reconcileCESCreate(cesName)
	} else if exists && desiredCEPsNumber > 0 {
		return r.reconcileCESUpdate(cesName, cesObj)
	} else if exists && desiredCEPsNumber == 0 {
		return r.reconcileCESDelete(cesObj)
	} else { // !exist && desiredCEPsNumber == 0 => no op
		return nil
	}
}

// Create a new CES in api-server.
func (r *reconciler) reconcileCESCreate(cesName CESName) (err error) {
	r.logger.Debug("Reconciling CES Create", logfields.CESName, cesName.string())
	ceps := r.cesManager.getCEPinCES(cesName)
	r.metrics.CiliumEndpointsChangeCount.WithLabelValues(LabelValueCEPInsert).Observe(float64(len(ceps)))
	newCES := &cilium_v2a1.CiliumEndpointSlice{
		TypeMeta: meta_v1.TypeMeta{
			Kind:       "CiliumEndpointSlice",
			APIVersion: cilium_v2.SchemeGroupVersion.String(),
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Name: cesName.string(),
		},
		Endpoints: make([]cilium_v2a1.CoreCiliumEndpoint, 0, len(ceps)),
	}

	cesData := r.cesManager.getCESData(cesName)
	newCES.Namespace = cesData.ns

	for _, cepName := range ceps {
		ccep := r.getCoreEndpointFromStore(cepName)
		r.logger.Debug(fmt.Sprintf("Adding CEP to new CES (exist %v)", ccep != nil),
			logfields.CESName, cesName.string(),
			logfields.CEPName, cepName.string())
		if ccep != nil {
			newCES.Endpoints = append(newCES.Endpoints, *ccep)
		}
	}

	// Call the client API, to Create CES
	if _, err = r.client.CiliumEndpointSlices().Create(
		r.context, newCES, meta_v1.CreateOptions{}); err != nil && !errors.Is(err, context.Canceled) {
		r.logger.Info("Unable to create CiliumEndpointSlice in k8s-apiserver",
			logfields.CESName, newCES.Name,
			logfields.Error, err)
	}
	return
}

// Update an existing CES
func (r *reconciler) reconcileCESUpdate(cesName CESName, cesObj *cilium_v2a1.CiliumEndpointSlice) (err error) {
	r.logger.Debug("Reconciling CES Update", logfields.CESName, cesName.string())
	updatedCES := cesObj.DeepCopy()
	cepInserted := 0
	cepRemoved := 0
	cepUpdated := 0

	// Names of all CEPs that should be in the CES
	cepsAssignedToCES := r.cesManager.getCEPinCES(cesName)
	// Final endpoints list. CES endpoints will be set to this list.
	updatedEndpoints := make([]cilium_v2a1.CoreCiliumEndpoint, 0, len(cepsAssignedToCES))
	cepNameToCEP := make(map[CEPName]*cilium_v2a1.CoreCiliumEndpoint)
	// Get the CEPs objects from the CEP Store and map the names to them
	for _, cepName := range cepsAssignedToCES {
		ccep := r.getCoreEndpointFromStore(cepName)
		r.logger.Debug(fmt.Sprintf("Adding CEP to existing CES (exist %v)", ccep != nil),
			logfields.CESName, cesName.string(),
			logfields.CEPName, cepName.string())
		if ccep != nil {
			updatedEndpoints = append(updatedEndpoints, *ccep)
			cepNameToCEP[cepName] = ccep
		}
		cepInserted = cepInserted + 1
	}
	// Grab metrics about number of inserted, updated and deleted CEPs and
	// determine whether CES needs to be updated at all.
	for _, ep := range updatedCES.Endpoints {
		epName := GetCEPNameFromCCEP(&ep, updatedCES.Namespace)
		if r.cesManager.isCEPinCES(epName, cesName) {
			cepInserted = cepInserted - 1
			if !ep.DeepEqual(cepNameToCEP[epName]) {
				cepUpdated = cepUpdated + 1
			}
		} else {
			cepRemoved = cepRemoved + 1
		}
	}
	updatedCES.Endpoints = updatedEndpoints
	r.logger.Debug(fmt.Sprintf("Inserted %d endpoints, updated %d endpoints, removed %d endpoints", cepInserted,
		cepUpdated, cepRemoved),
		logfields.CESName, cesName.string(),
	)

	cesEqual := cepInserted == 0 && cepUpdated == 0 && cepRemoved == 0
	data := r.cesManager.getCESData(cesName)
	if updatedCES.Namespace != data.ns {
		updatedCES.Namespace = data.ns
		cesEqual = false
	}

	r.metrics.CiliumEndpointsChangeCount.WithLabelValues(LabelValueCEPInsert).Observe(float64(cepInserted + cepUpdated))
	r.metrics.CiliumEndpointsChangeCount.WithLabelValues(LabelValueCEPRemove).Observe(float64(cepRemoved))

	if !cesEqual {
		r.logger.Debug("CES changed, updating", logfields.CESName, cesName.string())
		// Call the client API, to Create CESs
		if _, err = r.client.CiliumEndpointSlices().Update(
			r.context, updatedCES, meta_v1.UpdateOptions{}); err != nil && !errors.Is(err, context.Canceled) {
			r.logger.Info("Unable to update CiliumEndpointSlice in k8s-apiserver",
				logfields.CESName, updatedCES.Name,
				logfields.Error, err)
		}
	} else {
		r.logger.Debug("CES up to date, skipping update", logfields.CESName, cesName.string())
	}
	return
}

// Delete the CES.
func (r *reconciler) reconcileCESDelete(ces *cilium_v2a1.CiliumEndpointSlice) (err error) {
	r.logger.Debug("Reconciling CES Delete", logfields.CESName, ces.Name)
	r.metrics.CiliumEndpointsChangeCount.WithLabelValues(LabelValueCEPRemove).Observe(float64(len(ces.Endpoints)))
	if err = r.client.CiliumEndpointSlices().Delete(
		r.context, ces.Name, meta_v1.DeleteOptions{}); err != nil && !errors.Is(err, context.Canceled) {
		r.logger.Info("Unable to delete CiliumEndpointSlice in k8s-apiserver",
			logfields.CESName, ces.Name,
			logfields.Error, err)
		return
	}
	return
}

func (r *reconciler) getCoreEndpointFromStore(cepName CEPName) *cilium_v2a1.CoreCiliumEndpoint {
	cepObj, exists, err := r.cepStore.GetByKey(cepName.key())
	if err == nil && exists {
		return k8s.ConvertCEPToCoreCEP(cepObj)
	}
	r.logger.Debug(fmt.Sprintf("Couldn't get CEP from Store (err=%v, exists=%v)",
		err, exists),
		logfields.CEPName, cepName.string(),
	)
	return nil
}
