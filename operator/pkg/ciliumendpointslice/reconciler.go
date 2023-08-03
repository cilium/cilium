// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"

	"github.com/sirupsen/logrus"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// reconciler is used to sync the current (i.e. desired) state of the CESs in datastore into current state CESs in the k8s-apiserver.
// The source of truth is in local datastore.
type reconciler struct {
	client              clientset.CiliumV2alpha1Interface
	cesManager          operations
	ciliumEndpointStore cache.Store
}

// newReconciler creates and initializes a new reconciler.
func newReconciler(client clientset.CiliumV2alpha1Interface, cesMgr operations) *reconciler {
	return &reconciler{
		client:     client,
		cesManager: cesMgr,
	}
}

func (r *reconciler) reconcileCES(ces string) (err error) {
	cesName := CESName(ces)
	desiredCEPsNumber := r.cesManager.getCEPCountInCES(cesName)
	if operatorOption.Config.EnableMetrics {
		metrics.CiliumEndpointSliceDensity.Observe(float64(desiredCEPsNumber))
	}
	// Check the CES exists is in cesStore i.e. in api-server copy of CESs, if exist update or delete the CES.
	obj, exists, err := ceSliceStore.GetByKey(ces)
	if err != nil {
		return
	}
	var cesObj *cilium_v2a1.CiliumEndpointSlice = nil
	if obj != nil {
		cesObj = obj.(*cilium_v2a1.CiliumEndpointSlice)
	}
	if !exists && desiredCEPsNumber > 0 {
		return r.reconcileCESCreate(cesName)
	} else if exists && desiredCEPsNumber > 0 {
		return r.reconcileCESUpdate(cesName, cesObj)
	} else if exists && desiredCEPsNumber == 0 {
		return r.reconcileCESDelete(cesObj)
	} else { //!exist && desiredCEPsNumber == 0 => no op
		return nil
	}
}

// Create a new CES in api-server.
func (r *reconciler) reconcileCESCreate(cesName CESName) (err error) {
	log.WithFields(logrus.Fields{
		logfields.CESName: cesName,
	}).Debug("Reconciling CES Create.")
	ceps := r.cesManager.getCEPinCES(cesName)
	if operatorOption.Config.EnableMetrics {
		metrics.CiliumEndpointsChangeCount.WithLabelValues(metrics.LabelValueCEPInsert).Observe(float64(len(ceps)))
	}
	newCES := &cilium_v2a1.CiliumEndpointSlice{
		TypeMeta: meta_v1.TypeMeta{
			Kind:       "CiliumEndpointSlice",
			APIVersion: cilium_v2.SchemeGroupVersion.String(),
		},
		ObjectMeta: meta_v1.ObjectMeta{
			Name: string(cesName),
		},
		Endpoints: make([]cilium_v2a1.CoreCiliumEndpoint, 0, len(ceps)),
	}

	cesData := r.cesManager.getCESData(cesName)
	newCES.Namespace = cesData.ns

	for _, cepName := range ceps {
		ccep := r.getCoreEndpointFromStore(cepName)
		if ccep != nil {
			newCES.Endpoints = append(newCES.Endpoints, *ccep)
		}
	}

	// Call the client API, to Create CES
	if _, err = r.client.CiliumEndpointSlices().Create(
		context.TODO(), newCES, meta_v1.CreateOptions{}); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.CESName: newCES.Name,
		}).Info("Unable to create CiliumEndpointSlice in k8s-apiserver")
	}
	return
}

// Update an existing CES
func (r *reconciler) reconcileCESUpdate(cesName CESName, cesObj *cilium_v2a1.CiliumEndpointSlice) (err error) {
	log.WithFields(logrus.Fields{
		logfields.CESName: cesName,
	}).Debug("Reconciling CES Update.")
	updatedCES := cesObj.DeepCopy()
	cesEqual := true
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
		if ccep != nil {
			updatedEndpoints = append(updatedEndpoints, *ccep)
			cepNameToCEP[cepName] = ccep
		}
		cepInserted = cepInserted + 1
	}
	// Grab metrics about number of inserted, updated and deleted CEPs and
	// determine whether CES needs to be updated at all.
	for _, ep := range updatedCES.Endpoints {
		epName := CEPName(GetCEPNameFromCCEP(&ep, updatedCES.Namespace))
		if r.cesManager.isCEPinCES(epName, cesName) {
			cepInserted = cepInserted - 1
			if !ep.DeepEqual(cepNameToCEP[epName]) {
				cesEqual = false
				cepUpdated = cepUpdated + 1
			}
		} else {
			cesEqual = false
			cepRemoved = cepRemoved + 1
		}
	}
	updatedCES.Endpoints = updatedEndpoints
	log.WithFields(logrus.Fields{
		logfields.CESName: cesName,
	}).Debugf("Inserted %d endpoints, updated %d endpoints, removed %d endpoints", cepInserted, cepUpdated, cepRemoved)

	data := r.cesManager.getCESData(cesName)
	if updatedCES.Namespace != data.ns {
		updatedCES.Namespace = data.ns
		cesEqual = false
	}

	if operatorOption.Config.EnableMetrics {
		metrics.CiliumEndpointsChangeCount.WithLabelValues(metrics.LabelValueCEPInsert).Observe(float64(cepInserted + cepUpdated))
		metrics.CiliumEndpointsChangeCount.WithLabelValues(metrics.LabelValueCEPRemove).Observe(float64(cepRemoved))
	}

	if !cesEqual {
		log.WithFields(logrus.Fields{
			logfields.CESName: cesName,
		}).Debug("CES changed, updating")
		// Call the client API, to Create CESs
		if _, err = r.client.CiliumEndpointSlices().Update(
			context.TODO(), updatedCES, meta_v1.UpdateOptions{}); err != nil {
			log.WithError(err).WithFields(logrus.Fields{
				logfields.CESName: updatedCES.Name,
			}).Info("Unable to update CiliumEndpointSlice in k8s-apiserver")
		}
	} else {
		log.WithFields(logrus.Fields{
			logfields.CESName: cesName,
		}).Debug("CES up to date, skipping update")
	}
	return
}

// Delete the CES.
func (r *reconciler) reconcileCESDelete(ces *cilium_v2a1.CiliumEndpointSlice) (err error) {
	log.WithFields(logrus.Fields{
		logfields.CESName: ces.Name,
	}).Debug("Reconciling CES Delete.")
	if operatorOption.Config.EnableMetrics {
		metrics.CiliumEndpointsChangeCount.WithLabelValues(metrics.LabelValueCEPRemove).Observe(float64(len(ces.Endpoints)))
	}
	if err = r.client.CiliumEndpointSlices().Delete(
		context.TODO(), ces.Name, meta_v1.DeleteOptions{}); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.CESName: ces.Name,
		}).Info("Unable to delete CiliumEndpointSlice in k8s-apiserver")
		return
	}
	return
}

func (r *reconciler) getCoreEndpointFromStore(cepName CEPName) *cilium_v2a1.CoreCiliumEndpoint {
	cepObj, exists, err := r.ciliumEndpointStore.GetByKey(string(cepName))
	if err == nil && exists {
		return k8s.ConvertCEPToCoreCEP(cepObj.(*cilium_v2.CiliumEndpoint))
	}
	return nil
}
