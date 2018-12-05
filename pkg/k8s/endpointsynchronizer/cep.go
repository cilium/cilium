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
	"errors"
	"fmt"
	"github.com/cilium/cilium/pkg/k8s"
	"reflect"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	cilium_client_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	pkgLabels "github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/versioncheck"
	go_version "github.com/hashicorp/go-version"

	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	k8sToolsCache "k8s.io/client-go/tools/cache"
)

// CiliumEndpointGCInterval is the interval between attempts of the CEP GC
// controller.
// Note that only one node per cluster should run this, and most iterations
// will simply return.
const CiliumEndpointGCInterval = 30 * time.Minute

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

// CiliumEndpointSyncGC starts the node-singleton sweeper for
// CiliumEndpoint objects where the managing node is no longer running. These
// objects are created by the sync-to-k8s-ciliumendpoint controller on each
// Endpoint.
// The general steps are:
//   - get list of nodes
//   - only run with probability 1/nodes
//   - get list of CEPs
//   - for each CEP
//       delete CEP if the corresponding pod does not exist
// CiliumEndpoint objects have the same name as the pod they represent
func CiliumEndpointSyncGC(podStore k8sToolsCache.Store) {
	var (
		controllerName = fmt.Sprintf("sync-to-k8s-ciliumendpoint-gc (%v)", node.GetName())
		scopedLog      = log.WithField("controller", controllerName)
		firstRun       = true
	)

	if option.Config.DisableCiliumEndpointCRD {
		scopedLog.WithField("name", controllerName).Warn("Not running controller. CEP CRD synchronization is disabled")
		return
	}

	// this is a sanity check in case we are called with k8s not there
	if !k8s.IsEnabled() {
		scopedLog.WithField("name", controllerName).Warn("Not running controller because k8s is disabled")
		return
	}
	sv, err := k8s.GetServerVersion()
	if err != nil {
		scopedLog.WithError(err).Error("unable to retrieve kubernetes serverversion")
		return
	}
	if !ciliumEPControllerLimit.Check(sv) {
		scopedLog.WithFields(logrus.Fields{
			"expected": sv,
			"found":    ciliumEPControllerLimit,
		}).Warn("cannot run with this k8s version")
		return
	}

	ciliumClient, err := getCiliumClient()
	if err != nil {
		scopedLog.WithError(err).Error("Not starting controller because unable to get cilium k8s client")
		return
	}

	// this dummy manager is needed only to add this controller to the global list
	controller.NewManager().UpdateController(controllerName,
		controller.ControllerParams{
			RunInterval: CiliumEndpointGCInterval,
			DoFunc: func() error {
				// Don't run immediately
				if firstRun {
					firstRun = false
					return nil
				}

				// Only run if we are the "lowest" node in our cluster, when sorted by
				// names. This means only one node will ever run GCs in a given
				// cluster.
				thisNode := node.GetLocalNode().Identity()
				thisNodeStr := thisNode.String()
				for id := range node.GetNodes() {
					if idStr := id.String(); id.Cluster == thisNode.Cluster && idStr < thisNodeStr {
						scopedLog.WithField(logfields.Node, idStr).Debug("Skipping GC because another node is a better candidate")
						return nil
					}
				}

				var (
					listOpts = meta_v1.ListOptions{Limit: 10}
					loopStop = time.Now().Add(CiliumEndpointGCInterval)
				)

			perCEPFetch:
				for time.Now().Before(loopStop) { // Guard against no-break bugs
					time.Sleep(time.Second) // Throttle lookups in case of a busy loop

					ceps, err := ciliumClient.CiliumEndpoints(meta_v1.NamespaceAll).List(listOpts)
					switch {
					case err != nil && k8serrors.IsResourceExpired(err) && ceps.Continue != "":
						// This combination means we saw a 410 ResourceExpired error but we
						// can iterate on the now-current snapshot. We need to refetch,
						// however.
						// See https://github.com/kubernetes/apimachinery/blob/master/pkg/apis/meta/v1/types.go#L350-L381
						// or the docs for k8s.io/apimachinery/pkg/apis/meta/v1.ListOptions
						// vendored into this repo.
						listOpts.Continue = ceps.Continue
						continue perCEPFetch

					case err != nil:
						scopedLog.WithError(err).Debug("Cannot list CEPs")
						return err
					}

					// setup listOpts for the next iteration
					listOpts.Continue = ceps.Continue

					// For each CEP we fetched, check if we know about it
					for _, cep := range ceps.Items {
						cepFullName := cep.Namespace + "/" + cep.Name
						_, exists, err := podStore.GetByKey(cepFullName)
						if err != nil {
							return err
						}

						if !exists {
							// delete
							scopedLog = scopedLog.WithFields(logrus.Fields{
								logfields.EndpointID: cep.Status.ID,
								logfields.K8sPodName: cepFullName,
							})
							scopedLog.Debug("Orphaned CiliumEndpoint is being garbage collected")
							PropagationPolicy := meta_v1.DeletePropagationBackground // because these are const strings but the API wants pointers
							if err := ciliumClient.CiliumEndpoints(cep.Namespace).Delete(cep.Name, &meta_v1.DeleteOptions{PropagationPolicy: &PropagationPolicy}); err != nil {
								scopedLog.WithError(err).Debug("Unable to delete orphaned CEP")
								return err
							}
						}
					}
					if ceps.Continue != "" {
						// there is more data, continue
						continue perCEPFetch
					}
					break perCEPFetch // break out as a safe default to avoid spammy loops
				}
				return nil
			},
		})
}

// RunK8sCiliumEndpointSync starts a controller that synchronizes the endpoint
// to the corresponding k8s CiliumEndpoint CRD
// CiliumEndpoint objects have the same name as the pod they represent
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
		lastMdl      *models.Endpoint
		firstRun     = true
		k8sServerVer *go_version.Version // CEPs are not supported with certain versions
	)

	// NOTE: The controller functions do NOT hold the endpoint locks
	e.UpdateController(controllerName,
		controller.ControllerParams{
			RunInterval: 10 * time.Second,
			DoFunc: func() (err error) {
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

				mdl := e.GetModel()
				if reflect.DeepEqual(mdl, lastMdl) {
					scopedLog.Debug("Skipping CiliumEndpoint update because it has not changed")
					return nil
				}
				k8sMdl := (*cilium_v2.CiliumEndpointDetail)(mdl)

				cep, err := ciliumClient.CiliumEndpoints(namespace).Get(podName, meta_v1.GetOptions{})
				switch {
				// The CEP doesn't exist. We will fall through to the create code below
				case err != nil && k8serrors.IsNotFound(err):
					break

				// Delete the CEP on the first ever run. We will fall through to the create code below
				case firstRun:
					firstRun = false
					scopedLog.Debug("Deleting CEP on first run")
					err := ciliumClient.CiliumEndpoints(namespace).Delete(podName, &meta_v1.DeleteOptions{})
					if err != nil {
						scopedLog.WithError(err).Warn("Error deleting CEP")
						return err
					}

				// Delete an invalid CEP. We will fall through to the create code below
				case err != nil && k8serrors.IsInvalid(err):
					scopedLog.WithError(err).Warn("Invalid CEP during update")
					err := ciliumClient.CiliumEndpoints(namespace).Delete(podName, &meta_v1.DeleteOptions{})
					if err != nil {
						scopedLog.WithError(err).Warn("Error deleting invalid CEP during update")
						return err
					}

				// A real error
				case err != nil && !k8serrors.IsNotFound(err):
					scopedLog.WithError(err).Error("Cannot get CEP for update")
					return err

				// do an update
				case err == nil:
					// Update the copy of the cep
					k8sMdl.DeepCopyInto(&cep.Status)
					var err2 error
					switch {
					case ciliumUpdateStatusVerConstr.Check(k8sServerVer):
						_, err2 = ciliumClient.CiliumEndpoints(namespace).UpdateStatus(cep)
					default:
						_, err2 = ciliumClient.CiliumEndpoints(namespace).Update(cep)
					}
					if err2 != nil {
						scopedLog.WithError(err2).Error("Cannot update CEP")
						return err2
					}

					lastMdl = mdl
					return nil
				}

				// The CEP was not found, this is the first creation of the endpoint
				cep = &cilium_v2.CiliumEndpoint{
					ObjectMeta: meta_v1.ObjectMeta{
						Name: podName,
					},
					Status: *k8sMdl,
				}

				_, err = ciliumClient.CiliumEndpoints(namespace).Create(cep)
				if err != nil {
					scopedLog.WithError(err).Error("Cannot create CEP")
					return err
				}

				return nil
			},
			StopFunc: func() error {
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
