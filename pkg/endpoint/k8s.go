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

package endpoint

import (
	"errors"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_client_v2 "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"k8s.io/client-go/rest"

	"fmt"
	"github.com/cilium/cilium/pkg/controller"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/sirupsen/logrus"
	// todo check this is the right rand
	"math/rand"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"reflect"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	// ReservedCEPNamespace is the namespace to use for reserved endpoints that
	// don't have a namespace (e.g. health)
	ReservedCEPNamespace = meta_v1.NamespaceSystem

	// HealthCEPPrefix is the prefix used to name the cilium health endpoints' CEP
	HealthCEPPrefix = "cilium-health-"
)

// GetK8sNamespace returns the name of the pod if the endpoint represents a
// Kubernetes pod
func (e *Endpoint) GetK8sNamespace() string {
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()

	return e.k8sNamespace
}

// SetK8sNamespace modifies the endpoint's pod name
func (e *Endpoint) SetK8sNamespace(name string) {
	e.Mutex.Lock()
	e.k8sNamespace = name
	e.Mutex.Unlock()
}

// GetK8sPodName returns the name of the pod if the endpoint represents a
// Kubernetes pod
func (e *Endpoint) GetK8sPodName() string {
	e.Mutex.RLock()
	defer e.Mutex.RUnlock()

	return e.k8sPodName
}

// GetK8sNamespaceAndPodNameLocked returns the namespace and pod name.  This
// function requires e.Mutex to be held.
func (e *Endpoint) GetK8sNamespaceAndPodNameLocked() string {
	return e.k8sNamespace + ":" + e.k8sPodName
}

// SetK8sPodName modifies the endpoint's pod name
func (e *Endpoint) SetK8sPodName(name string) {
	e.Mutex.Lock()
	e.k8sPodName = name
	e.Mutex.Unlock()
}

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

// RunK8sCiliumEndpointSyncGC starts the node-singleton sweeper for
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
// RunK8sCiliumEndpointSyncGC starts the node-singleton sweeper for
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
func RunK8sCiliumEndpointSyncGC() {
	var (
		controllerName = fmt.Sprintf("sync-to-k8s-ciliumendpoint-gc (%v)", node.GetName())
		scopedLog      = log.WithField("controller", controllerName)

		// random source to throttle how often this controller runs cluster-wide
		runThrottler = rand.New(rand.NewSource(time.Now().UnixNano()))
	)

	// this is a sanity check
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
	k8sClient := k8s.Client()

	// this dummy manager is needed only to add this controller to the global list
	controller.NewManager().UpdateController(controllerName,
		controller.ControllerParams{
			RunInterval: 1 * time.Minute,
			DoFunc: func() error {
				// Don't run if there are no other known nodes
				// Only run with a probability of 1/(number of nodes in cluster). This
				// is because this controller runs on every node on the same interval
				// but only one is neede to run.
				nodes := node.GetNodes()
				if len(nodes) <= 1 || runThrottler.Int63n(int64(len(nodes))) != 0 {
					return nil
				}

				clusterPodSet := map[string]bool{}
				clusterPods, err := k8sClient.CoreV1().Pods("").List(meta_v1.ListOptions{})
				if err != nil {
					return err
				}
				for _, pod := range clusterPods.Items {
					podFullName := pod.Name + ":" + pod.Namespace
					clusterPodSet[podFullName] = true
				}

				// "" is all-namespaces
				ceps, err := ciliumClient.CiliumEndpoints(meta_v1.NamespaceAll).List(meta_v1.ListOptions{})
				if err != nil {
					scopedLog.WithError(err).Debug("Cannot list CEPs")
					return err
				}
				for _, cep := range ceps.Items {
					cepFullName := cep.Name + ":" + cep.Namespace
					if _, found := clusterPodSet[cepFullName]; !found {
						// delete
						scopedLog = scopedLog.WithFields(logrus.Fields{
							logfields.EndpointID: cep.Status.ID,
							logfields.K8sPodName: cepFullName,
						})
						scopedLog.Debug("Orphaned CiliumEndpoint is being garbage collected")
						if err := ciliumClient.CiliumEndpoints(cep.Namespace).Delete(cep.Name, &meta_v1.DeleteOptions{}); err != nil {
							scopedLog.WithError(err).Debug("Unable to delete CEP")
							return err
						}
					}
				}
				return nil
			},
		})
}

// RunK8sCiliumEndpointSync starts a controller that syncronizes the endpoint
// to the corresponding k8s CiliumEndpoint CRD
// CiliumEndpoint objects have the same name as the pod they represent
func (e *Endpoint) RunK8sCiliumEndpointSync() {
	var (
		endpointID     = e.ID
		controllerName = fmt.Sprintf("sync-to-k8s-ciliumendpoint (%v)", endpointID)
		scopedLog      = e.getLogger().WithField("controller", controllerName)
		healthLbls     = labels.Labels{labels.IDNameHealth: labels.NewLabel(labels.IDNameHealth, "", labels.LabelSourceReserved)}
	)

	if !k8s.IsEnabled() {
		scopedLog.Debug("Not starting controller because k8s is disabled")
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

	var (
		lastMdl  *models.Endpoint
		firstRun = true
	)

	// NOTE: The controller functions do NOT hold the endpoint locks
	e.controllers.UpdateController(controllerName,
		controller.ControllerParams{
			RunInterval: 10 * time.Second,
			DoFunc: func() (err error) {
				var (
					podName    string
					namespace  string
					isHealthEP = e.HasLabels(healthLbls)
				)

				switch isHealthEP {
				case true:
					podName = HealthCEPPrefix + node.GetName()
					namespace = ReservedCEPNamespace

				case false:
					podName = e.GetK8sPodName()
					if podName == "" {
						scopedLog.Debug("Skipping CiliumEndpoint update because it has no k8s pod name")
						return nil
					}

					namespace = e.GetK8sNamespace()
					if namespace == "" {
						scopedLog.Debug("Skipping CiliumEndpoint update because it has no k8s namespace")
						return nil
					}
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

					if _, err = ciliumClient.CiliumEndpoints(namespace).Update(cep); err != nil {
						scopedLog.WithError(err).Error("Cannot update CEP")
						return err
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
