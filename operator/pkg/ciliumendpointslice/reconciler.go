// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// reconciler is used to sync the current (i.e. desired) state of the CESs in datastore into current state CESs in the k8s-apiserver.
// The source of truth is in local datastore.
type reconciler struct {
	client     clientset.CiliumV2alpha1Interface
	cesManager operations
}

// newReconciler creates and initializes a new reconciler.
func newReconciler(client clientset.CiliumV2alpha1Interface, cesMgr operations) *reconciler {
	return &reconciler{
		client:     client,
		cesManager: cesMgr,
	}
}

// Create a new CES in api-server.
func (r *reconciler) reconcileCESCreate(cesToCreate string) (err error) {
	var retCES, ces *cilium_v2.CiliumEndpointSlice
	// Get the copy of CES from the cesManager
	if ces, err = r.cesManager.getCESCopyFromCache(cesToCreate); err != nil {
		return
	}

	if len(ces.Endpoints) == 0 {
		// The CES is empty, delete ces information from cache rather than creating
		// empty CES.
		r.cesManager.deleteCESFromCache(cesToCreate)
		return
	}

	// Call the client API, to Create CES
	if retCES, err = r.client.CiliumEndpointSlices().Create(
		context.TODO(), ces, metav1.CreateOptions{}); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.CESName: cesToCreate,
		}).Info("Unable to create CiliumEndpointSlice in k8s-apiserver")
		return
	}
	// Update local datastore CES with latest object metadata values.
	r.cesManager.updateCESInCache(retCES, false)
	return
}

// Update an existing CES
func (r *reconciler) reconcileCESUpdate(cesToUpdate string) (err error) {
	var retCES, ces *cilium_v2.CiliumEndpointSlice

	// Before syncing with ApiServer, get list of removed CEPs
	remCEPs := r.cesManager.getRemovedCEPs(cesToUpdate)
	// Get the copy of CES from the cesManager
	if ces, err = r.cesManager.getCESCopyFromCache(cesToUpdate); err != nil {
		return
	}

	// Call the client API, to Create CESs
	if retCES, err = r.client.CiliumEndpointSlices().Update(
		context.TODO(), ces, metav1.UpdateOptions{}); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.CESName: cesToUpdate,
		}).Info("Unable to update CiliumEndpointSlice in k8s-apiserver")
		return
	}
	// Update local datastore CES with latest object metadata values.
	r.cesManager.updateCESInCache(retCES, false)
	// Since local copy of CES is synced with api-server, we don't need to track anymore removed
	// CEPS.
	r.cesManager.clearRemovedCEPs(cesToUpdate, remCEPs)
	return
}

// Delete the CES.
func (r *reconciler) reconcileCESDelete(cesToDelete string) (err error) {
	if err = r.client.CiliumEndpointSlices().Delete(
		context.TODO(), cesToDelete, metav1.DeleteOptions{}); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			logfields.CESName: cesToDelete,
		}).Info("Unable to delete CiliumEndpointSlice in k8s-apiserver")
		return
	}
	// Delete ces information from cache
	r.cesManager.deleteCESFromCache(cesToDelete)
	return
}
