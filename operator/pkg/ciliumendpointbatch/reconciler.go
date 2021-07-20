// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ciliumendpointbatch

import (
	"context"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
)

// reconciler is used to sync the current (i.e. desired) state of the CEBs in datastore into current state CEBs in the k8s-apiserver.
// The source of truth is in local datastore.
type reconciler struct {
	client     clientset.CiliumV2alpha1Interface
	cebManager cebManager
}

// newReconciler creates and initializes a new reconciler.
func newReconciler(client clientset.CiliumV2alpha1Interface, cebMgr cebManager) *reconciler {
	return &reconciler{
		client:     client,
		cebManager: cebMgr,
	}
}

// Create a new CEB in api-server.
func (r *reconciler) reconcileCebCreate(cebToCreate string) (err error) {
	var retCeb, ceb *cilium_v2.CiliumEndpointBatch
	// Get the copy of Ceb from the cebManager
	if ceb, err = r.cebManager.getCebCopyFromCache(cebToCreate); err != nil {
		return
	}

	// Call the client API, to Create CEB
	if retCeb, err = r.client.CiliumEndpointBatches().Create(
		context.TODO(), ceb, metav1.CreateOptions{}); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			"ceb-name": cebToCreate,
		}).Error("Error Creating CiliumEndpointBatch")
		return
	}
	// Update local datastore CEB with latest object metadata values.
	r.cebManager.updateCebInCache(retCeb, false)
	return
}

// Update an existing CEB
func (r *reconciler) reconcileCebUpdate(cebToUpdate string) (err error) {
	var retCeb, ceb *cilium_v2.CiliumEndpointBatch

	// Before syncing with ApiServer, get list of removed CEPs
	remCeps := r.cebManager.getRemovedCeps(cebToUpdate)
	// Get the copy of Ceb from the cebManager
	if ceb, err = r.cebManager.getCebCopyFromCache(cebToUpdate); err != nil {
		return
	}

	// Call the client API, to Create CEBs
	if retCeb, err = r.client.CiliumEndpointBatches().Update(
		context.TODO(), ceb, metav1.UpdateOptions{}); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			"ceb-name": cebToUpdate,
		}).Error("Error Updating CiliumEndpointBatch")
		return
	}
	// Update local datastore CEB with latest object metadata values.
	r.cebManager.updateCebInCache(retCeb, false)
	// Since local copy of CEB is synced with api-server, we don't need to track anymore removed
	// CEPS.
	r.cebManager.clearRemovedCeps(cebToUpdate, remCeps)
	return
}

// Delete the CEB.
func (r *reconciler) reconcileCebDelete(cebToDelete string) (err error) {
	if err = r.client.CiliumEndpointBatches().Delete(
		context.TODO(), cebToDelete, metav1.DeleteOptions{}); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			"ceb-name": cebToDelete,
		}).Error("Error Deleting CiliumEndpointBatch")
		return
	}
	// Delete ceb information from cache
	r.cebManager.deleteCebFromCache(cebToDelete)
	return
}
