// Copyright 2016-2018 Authors of Cilium
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

package endpointsynchronizer

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cilium/cilium/pkg/k8s"
	"reflect"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	pkgLabels "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// EndpointSynchronizer currently is an empty type, which wraps around syncing
// of CiliumEndpoint resources.
// TODO - see whether folding the global variables below into this function
// is cleaner.
type EndpointSynchronizer struct{}

// RunK8sCiliumEndpointSync starts a controller that synchronizes the endpoint
// to the corresponding k8s CiliumEndpoint CRD. It is expected that each CEP
// has 1 controller that updates it, and a local copy is retained and only
// updates are pushed up.
// CiliumEndpoint objects have the same name as the pod they represent.
func (epSync *EndpointSynchronizer) RunK8sCiliumEndpointSync(e *endpoint.Endpoint) {
	var (
		endpointID     = e.ID
		controllerName = fmt.Sprintf("sync-to-k8s-ciliumendpoint (%v)", endpointID)
		scopedLog      = e.Logger(subsysEndpointSync).WithField("controller", controllerName)
	)

	if option.Config.DisableCiliumEndpointCRD {
		scopedLog.Warn("Not running controller. CEP CRD synchronization is disabled")
		return
	}

	if !k8s.IsEnabled() {
		scopedLog.Debug("Not starting controller because k8s is disabled")
		return
	}

	ciliumClient := k8s.CiliumClient().CiliumV2()

	// The health endpoint doesn't really exist in k8s and updates to it caused
	// arbitrary errors. Disable the controller for these endpoints.
	if isHealthEP := e.HasLabels(pkgLabels.LabelHealth); isHealthEP {
		scopedLog.Debug("Not starting unnecessary CEP controller for cilium-health endpoint")
		return
	}

	var (
		lastMdl  *cilium_v2.EndpointStatus
		localCEP *cilium_v2.CiliumEndpoint // the local copy of the CEP object. Reused.
		needInit = true                    // needInit indicates that we may need to create the CEP
	)

	// NOTE: The controller functions do NOT hold the endpoint locks
	e.UpdateController(controllerName,
		controller.ControllerParams{
			RunInterval: 10 * time.Second,
			DoFunc: func(ctx context.Context) (err error) {
				// Update logger as scopeLog might not have the podName when it
				// was created.
				scopedLog = e.Logger(subsysEndpointSync).WithField("controller", controllerName)

				if k8sversion.Version() == nil {
					return fmt.Errorf("Kubernetes apiserver is not available")
				}

				capabilities := k8sversion.Capabilities()

				// K8sPodName and K8sNamespace are not always available when an
				// endpoint is first created, so we collect them here.
				podName := e.GetK8sPodName()
				if podName == "" {
					scopedLog.Debug("Skipping CiliumEndpoint update because it has no k8s pod name")
					return nil
				}

				namespace := e.GetK8sNamespace()
				if namespace == "" {
					scopedLog.Debug("Skipping CiliumEndpoint update because it has no k8s namespace")
					return nil
				}

				// Serialize the endpoint into a model. It is compared with the one
				// from before, only updating on changes.
				mdl := e.GetCiliumEndpointStatus()
				if reflect.DeepEqual(mdl, lastMdl) {
					scopedLog.Debug("Skipping CiliumEndpoint update because it has not changed")
					return nil
				}

				// Initialize the CEP by deleting the upstream instance and recreating
				// it. Deleting first allows for upgrade scenarios where the format has
				// changed but our k8s CEP code cannot read in the upstream value.
				if needInit {
					state := e.GetState()
					// Don't bother to create if the
					// endpoint is already disconnecting
					if state == endpoint.StateDisconnecting ||
						state == endpoint.StateDisconnected {
						return nil
					}

					scopedLog.Debug("Deleting CEP during an initialization")
					err := ciliumClient.CiliumEndpoints(namespace).Delete(podName, &meta_v1.DeleteOptions{})
					// It's only an error if it exists but something else happened
					if err != nil && !k8serrors.IsNotFound(err) {
						scopedLog.WithError(err).Warn("Error deleting CEP")
						return err
					}

					// We can't create localCEP directly, it must come from the k8s
					// server via an API call.
					cep := &cilium_v2.CiliumEndpoint{
						ObjectMeta: meta_v1.ObjectMeta{
							Name: podName,
						},
						Status: *mdl,
					}
					localCEP, err = ciliumClient.CiliumEndpoints(namespace).Create(cep)
					if err != nil {
						scopedLog.WithError(err).Error("Cannot create CEP")
						return err
					}

					// We have successfully created the CEP and can return. Subsequent
					// runs will update using localCEP.
					needInit = false
					return nil
				}

				// We have no localCEP copy. We need to fetch it for updates, below.
				// This is unexpected as there should be only 1 writer per CEP, this
				// controller, and the localCEP created on startup will be used.
				if localCEP == nil {
					localCEP, err = ciliumClient.CiliumEndpoints(namespace).Get(podName, meta_v1.GetOptions{})
					switch {
					// The CEP doesn't exist in k8s. This is unexpetected but may occur
					// if the endpoint was removed from k8s but not yet within the agent.
					// Mark the CEP for creation on the next controller iteration. This
					// may never occur if the controller is stopped on Endpoint delete.
					case err != nil && k8serrors.IsNotFound(err):
						needInit = true
						return err

					// We cannot read the upstream CEP. needInit will cause the next
					// iteration to delete and create the CEP. This is an unexpected
					// situation.
					case err != nil && k8serrors.IsInvalid(err):
						scopedLog.WithError(err).Warn("Invalid CEP during update")
						needInit = true
						return nil

					// A real error
					case err != nil:
						scopedLog.WithError(err).Error("Cannot get CEP during update")
						return err
					}
				}

				switch {
				case capabilities.Patch:
					// For json patch we don't need to perform a GET for endpoints

					// If it fails it means the test from the previous patch failed
					// so we can safely replace this node in the CNP status.
					replaceCEPStatus := []k8s.JSONPatch{
						{
							OP:    "replace",
							Path:  "/status",
							Value: mdl,
						},
					}
					var createStatusPatch []byte
					createStatusPatch, err = json.Marshal(replaceCEPStatus)
					if err != nil {
						return err
					}
					localCEP, err = ciliumClient.CiliumEndpoints(namespace).Patch(podName, types.JSONPatchType, createStatusPatch, "status")
				default:
					// We have an object to reuse. Update and push it up. In the case of an
					// update error, we retry in the next iteration of the controller using
					// the copy returned by Update.
					scopedLog.Debug("Updating CEP from local copy")
					mdl.DeepCopyInto(&localCEP.Status)
					switch {
					case capabilities.UpdateStatus:
						localCEP, err = ciliumClient.CiliumEndpoints(namespace).UpdateStatus(localCEP)
					default:
						localCEP, err = ciliumClient.CiliumEndpoints(namespace).Update(localCEP)
					}
				}

				// Handle Update errors or return successfully
				switch {
				// Return no error when we see a conflict. We want to retry without a
				// backoff and the Update* calls returned the current localCEP
				case err != nil && k8serrors.IsConflict(err):
					scopedLog.WithError(err).Warn("Cannot update CEP due to a revision conflict. The next controller execution will try again")
					return nil

				// Ensure we re-init when we see a generic error. This will recrate the
				// CEP.
				case err != nil:
					scopedLog.WithError(err).Error("Cannot update CEP")
					needInit = true
					return err

				// A successful update means no more updates unless mdl changes
				default:
					lastMdl = mdl
					return nil
				}
			},
			StopFunc: func(ctx context.Context) error {
				podName := e.GetK8sPodName()
				namespace := e.GetK8sNamespace()
				if err := ciliumClient.CiliumEndpoints(namespace).Delete(podName, &meta_v1.DeleteOptions{}); err != nil {
					if !k8serrors.IsNotFound(err) {
						scopedLog.WithError(err).Warning("Unable to delete CEP")
					}
				}
				return nil
			},
		})
}
