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

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2alpha1"
)

// reconciler is used to sync the current[i.e. desired] state of CEB's in datastore into current state CEB's in k8s-apiserver.
// The source of truth is in local datastore, client code reconcile with apiserver at regular intervals.
type reconciler struct {
	client     clientset.CiliumV2alpha1Interface
	cebManager cebManager
}

// Create and Initializes new reconciler.
func newReconciler(client clientset.CiliumV2alpha1Interface, cebMgr cebManager) *reconciler {
	return &reconciler{
		client:     client,
		cebManager: cebMgr,
	}
}

// reconcileWithServer gets the list of ceb's to create, update and delete and syncs with api-server.
// On error, it returns the list of failed createCebs, updateCebs and deleteCebs to the caller.
func (r *reconciler) reconcileWithServer(cebsToCreate, cebsToUpdate, cebsToDelete []string) (errCebCreate, errCebUpdate, errCebDelete []string) {
	var ok, err error
	var retCeb, ceb *cilium_v2.CiliumEndpointBatch

	// Loop through list of cebsToCreate and create a new CEB
	for _, c := range cebsToCreate {
		// Get the copy of Ceb from the cebManager
		if ceb, ok = r.cebManager.getCebFromCache(c); ok != nil {
			continue
		}

		// Call the client API, to Create CEBs
		if retCeb, err = r.client.CiliumEndpointBatches().Create(
			context.TODO(), ceb, metav1.CreateOptions{}); err != nil {
			// On Error, append ceb name in errCebCreate
			log.WithError(err).Infof("Error Creating CiliumEndpointBatch :%s", c)
			errCebCreate = append(errCebCreate, c)
			continue
		}
		// Update local datastore CEB with latest object metadata values.
		r.cebManager.updateCebInCache(retCeb, false)
	}

	// Loop through list of cebsToUpdate and update the CEB
	for _, c := range cebsToUpdate {

		// Get the copy of Ceb from the cebManager
		if ceb, ok = r.cebManager.getCebFromCache(c); ok != nil {
			continue
		}

		if retCeb, err = r.client.CiliumEndpointBatches().Update(
			context.TODO(), ceb, metav1.UpdateOptions{}); err != nil {

			// If CEB is not found in server, log the error and don't append in errcebUpdate.
			if errors.IsNotFound(err) {
				log.WithError(err).Infof("Error from server CEB is NotFound in server :%s", ceb.GetName())
			} else {
				log.WithError(err).Infof("Error Updating CiliumEndpointBatch :%s", c)
				errCebUpdate = append(errCebUpdate, c)
			}
			continue
		}
		// Update local datastore CEB with latest object metadata values.
		r.cebManager.updateCebInCache(retCeb, false)
	}

	// Loop through list of cebsToDelete and delete the CEB
	for _, c := range cebsToDelete {
		if err := r.client.CiliumEndpointBatches().Delete(
			context.TODO(), c, metav1.DeleteOptions{}); err != nil {

			// If CEB is not found in server, log the error and don't append in errcebUpdate.
			if errors.IsNotFound(err) {
				log.WithError(err).Infof("Error from server CEB is NotFound in server :%s", ceb.GetName())
				r.cebManager.deleteCebFromCache(c)
			} else {
				log.WithError(err).Debugf("Error Deleting CiliumEndpointBatch :%s", c)
				errCebDelete = append(errCebDelete, c)
			}
			continue
		}
		r.cebManager.deleteCebFromCache(c)
	}

	return
}
