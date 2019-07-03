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

package main

import (
	"context"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	core_v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	// ciliumEndpointGCInterval is the interval between attempts of the CEP GC
	// controller.
	// Note that only one node per cluster should run this, and most iterations
	// will simply return.
	ciliumEndpointGCInterval time.Duration
)

// enableCiliumEndpointSyncGC starts the node-singleton sweeper for
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
func enableCiliumEndpointSyncGC() {
	var (
		controllerName = "to-k8s-ciliumendpoint-gc"
		scopedLog      = log.WithField("controller", controllerName)
	)

	log.Info("Starting to garbage collect stale CiliumEndpoint custom resources...")

	ciliumClient := ciliumK8sClient.CiliumV2()

	// this dummy manager is needed only to add this controller to the global list
	controller.NewManager().UpdateController(controllerName,
		controller.ControllerParams{
			RunInterval: ciliumEndpointGCInterval,
			DoFunc: func(ctx context.Context) error {
				var (
					listOpts = meta_v1.ListOptions{Limit: 10}
					loopStop = time.Now().Add(ciliumEndpointGCInterval)
				)

				pods, err := k8s.Client().CoreV1().Pods("").List(meta_v1.ListOptions{})
				if err != nil {
					return err
				}

				podsCache := map[string]*core_v1.Pod{}
				for _, pod := range pods.Items {
					podsCache[pod.Namespace+"/"+pod.Name] = &pod
				}

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
						_, exists := podsCache[cepFullName]
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
