// Copyright 2016-2020 Authors of Cilium
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

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// enableCiliumEndpointSyncGC starts the node-singleton sweeper for
// CiliumEndpoint objects where the managing node is no longer running. These
// objects are created by the sync-to-k8s-ciliumendpoint controller on each
// Endpoint.
// The general steps are:
//   - list all CEPs in the cluster
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

	// This functions will block until the resources are synced with k8s.
	watchers.CiliumEndpointsInit(ciliumClient)
	watchers.PodsInit(k8s.WatcherCli())

	// this dummy manager is needed only to add this controller to the global list
	controller.NewManager().UpdateController(controllerName,
		controller.ControllerParams{
			RunInterval: operatorOption.Config.EndpointGCInterval,
			DoFunc: func(ctx context.Context) error {
				// For each CEP we fetched, check if we know about it
				for _, cepObj := range watchers.CiliumEndpointStore.List() {
					cep, ok := cepObj.(*cilium_v2.CiliumEndpoint)
					if !ok {
						log.WithField(logfields.Object, cepObj).
							Errorf("Saw %T object while expecting *cilium_v2.CiliumEndpoint", cepObj)
						continue
					}

					cepFullName := cep.Namespace + "/" + cep.Name
					_, exists, err := watchers.PodStore.GetByKey(cepFullName)
					if err != nil {
						scopedLog.WithError(err).Warn("Unable to get pod from store")
						continue
					}
					if !exists {
						// FIXME: this is fragile as we might have received the
						// CEP notification first but not the pod notification
						// so we need to have a similar mechanism that we have
						// for the keep alive of security identities.
						scopedLog = scopedLog.WithFields(logrus.Fields{
							logfields.EndpointID: cep.Status.ID,
							logfields.K8sPodName: cepFullName,
						})
						scopedLog.Debug("Orphaned CiliumEndpoint is being garbage collected")
						PropagationPolicy := meta_v1.DeletePropagationBackground // because these are const strings but the API wants pointers
						err := ciliumClient.CiliumEndpoints(cep.Namespace).Delete(
							ctx,
							cep.Name,
							meta_v1.DeleteOptions{PropagationPolicy: &PropagationPolicy})
						if !k8serrors.IsNotFound(err) {
							scopedLog.WithError(err).Warning("Unable to delete orphaned CEP")
							return err
						}
					}
				}
				return nil
			},
		})
}
