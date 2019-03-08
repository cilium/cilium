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
	"errors"
	"fmt"
	"github.com/cilium/cilium/pkg/k8s"
	"reflect"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	cilium_client_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	pkgLabels "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/versioncheck"
	go_version "github.com/hashicorp/go-version"

	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
)

// EndpointSynchronizer currently is an empty type, which wraps around syncing
// of CiliumEndpoint resources.
// TODO - see whether folding the global variables below into this function
// is cleaner.
type EndpointSynchronizer struct{}

var (
	// ciliumEPControllerLimit is the range of k8s versions with which we are
	// willing to run the EndpointCRD controllers
	ciliumEPControllerLimit = versioncheck.MustCompile("> 1.6")

	// ciliumEndpointSyncControllerK8sClient is a k8s client shared by the
	// RunK8sCiliumEndpointSync and CiliumEndpointSyncGC. They obtain the
	// controller via getCiliumClient and the sync.Once is used to avoid race.
	ciliumEndpointSyncControllerOnce      sync.Once
	ciliumEndpointSyncControllerK8sClient clientset.Interface

	// ciliumUpdateStatusVerConstr is the minimal version supported for
	// to perform a CRD UpdateStatus.
	ciliumUpdateStatusVerConstr = versioncheck.MustCompile(">= 1.11.0")
)

// getCiliumClient builds and returns a k8s auto-generated client for cilium
// objects
func getCiliumClient() (ciliumClient cilium_client_v2.CiliumV2Interface, err error) {
	// This allows us to reuse the k8s client
	ciliumEndpointSyncControllerOnce.Do(func() {
		var (
			restConfig *rest.Config
			k8sClient  *clientset.Clientset
		)

		restConfig, err = k8s.CreateConfig()
		if err != nil {
			return
		}

		k8sClient, err = clientset.NewForConfig(restConfig)
		if err != nil {
			return
		}

		ciliumEndpointSyncControllerK8sClient = k8sClient
	})

	if err != nil {
		return nil, err
	}

	// This guards against the situation where another invocation of this
	// function (in another thread or previous in time) might have returned an
	// error and not initialized ciliumEndpointSyncControllerK8sClient
	if ciliumEndpointSyncControllerK8sClient == nil {
		return nil, errors.New("No initialised k8s Cilium CRD client")
	}

	return ciliumEndpointSyncControllerK8sClient.CiliumV2(), nil
}

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
		err            error
	)

	if option.Config.DisableCiliumEndpointCRD {
		scopedLog.Warn("Not running controller. CEP CRD synchronization is disabled")
		return
	}

	if !k8s.IsEnabled() {
		scopedLog.Debug("Not starting controller because k8s is disabled")
		return
	}

	ciliumClient, err := getCiliumClient()
	if err != nil {
		scopedLog.WithError(err).Error("Not starting controller because unable to get cilium k8s client")
		return
	}

	// The health endpoint doesn't really exist in k8s and updates to it caused
	// arbitrary errors. Disable the controller for these endpoints.
	if isHealthEP := e.HasLabels(pkgLabels.LabelHealth); isHealthEP {
		scopedLog.Debug("Not starting unnecessary CEP controller for cilium-health endpoint")
		return
	}

	var (
		lastMdl      *cilium_v2.EndpointStatus
		localCEP     *cilium_v2.CiliumEndpoint // the local copy of the CEP object. Reused.
		needInit     = true                    // needInit indicates that we may need to create the CEP
		k8sServerVer *go_version.Version       // CEPs are not supported with certain versions
	)

	// NOTE: The controller functions do NOT hold the endpoint locks
	e.UpdateController(controllerName,
		controller.ControllerParams{
			RunInterval: 10 * time.Second,
			DoFunc: func(ctx context.Context) (err error) {
				// Update logger as scopeLog might not have the podName when it
				// was created.
				scopedLog = e.Logger(subsysEndpointSync).WithField("controller", controllerName)

				// This lookup can fail but once we do it once, we no longer want to try again.
				if k8sServerVer == nil {
					var err error
					k8sServerVer, err = k8s.GetServerVersion()
					switch {
					case err != nil:
						scopedLog.WithError(err).Error("Unable to retrieve kubernetes server version")
						return err

					case !ciliumEPControllerLimit.Check(k8sServerVer):
						scopedLog.WithFields(logrus.Fields{
							"found":    k8sServerVer,
							"expected": ciliumEPControllerLimit,
						}).Warn("Cannot run with this k8s version")
						return nil
					}
				}
				if k8sServerVer == nil || !ciliumEPControllerLimit.Check(k8sServerVer) {
					return nil // silently return when k8s is incompatible
				}

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
				case k8s.JSONPatchVerConstr.Check(k8sServerVer) || option.Config.K8sForceJSONPatch:
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
					case ciliumUpdateStatusVerConstr.Check(k8sServerVer):
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
					scopedLog.WithError(err).Error("Unable to delete CEP")
					return err
				}
				return nil
			},
		})
}
