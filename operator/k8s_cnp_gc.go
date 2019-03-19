// Copyright 2019 Authors of Cilium
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
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/typed/cilium.io/v2"
	"github.com/cilium/cilium/pkg/versioncheck"

	"github.com/sirupsen/logrus"
	core_v1 "k8s.io/api/core/v1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ciliumEndpointGCInterval is the interval between attempts of the CEP GC
// controller.
// Note that only one node per cluster should run this, and most iterations
// will simply return.
const (
	ciliumEndpointGCInterval = 30 * time.Minute
	parallelRequests         = 3
)

var (
	// ciliumEPControllerLimit is the range of k8s versions with which we are
	// willing to run the EndpointCRD controllers
	ciliumEPControllerLimit = versioncheck.MustCompile("> 1.6")

	removeNodeFromCNP = make(chan cilium_v2.CiliumNetworkPolicy, 50)
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
func enableCiliumCNPNodesGC() {
	var (
		controllerName = "to-k8s-ciliumnetworkpolicy-node-status-gc"
		scopedLog      = log.WithField("controller", controllerName)
	)

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

	ciliumClient := ciliumK8sClient.CiliumV2()

	for i := 0; i < parallelRequests; i++ {
		go func() {
			for cnp := range removeNodeFromCNP {
				updateCNP(ciliumClient, &cnp)
			}
		}()
	}

	// this dummy manager is needed only to add this controller to the global list
	controller.NewManager().UpdateController(controllerName,
		controller.ControllerParams{
			RunInterval: ciliumEndpointGCInterval,
			DoFunc: func(ctx context.Context) error {
				nodes := map[string]struct{}{}
				newNodes := map[string]struct{}{}
				continueID := ""
				nodeResourceVer := ""
				for {
					cnpList, err := ciliumClient.CiliumNetworkPolicies(core_v1.NamespaceAll).List(meta_v1.ListOptions{
						Limit:    10,
						Continue: continueID,
					})

					newNodes, nodeResourceVer, err = getAllNodes(k8s.Client(), nodeResourceVer)
					if err != nil {
						return err
					}
					for k, v := range newNodes {
						nodes[k] = v
					}

					for _, cnp := range cnpList.Items {
						for node := range cnp.Status.Nodes {
							if _, ok := nodes[node]; !ok {
								delete(cnp.Status.Nodes, node)
							}
						}
						removeNodeFromCNP <- cnp
					}

					continueID = cnpList.Continue
					if continueID == "" {
						break
					}
				}
				return nil
			},
		})
}

func getAllNodes(k8sClient kubernetes.Interface, resourceVersion string) (map[string]struct{}, string, error) {
	nodes := map[string]struct{}{}

	for continueID := ""; ; {
		nol, err := k8sClient.CoreV1().Nodes().List(meta_v1.ListOptions{
			ResourceVersion: resourceVersion,
			Limit:           50,
			Continue:        continueID,
		})
		if err != nil {
			return nil, "", err
		}

		for _, node := range nol.Items {
			nodes[node.Name] = struct{}{}
		}

		continueID = nol.Continue
		if continueID == "" {
			return nodes, nol.ResourceVersion, nil
		}
	}
}

func updateCNP(ciliumClient v2.CiliumV2Interface, cnp *cilium_v2.CiliumNetworkPolicy) (*cilium_v2.CiliumNetworkPolicy, error) {
	cnpReply, err := ciliumClient.CiliumNetworkPolicies(cnp.Namespace).UpdateStatus(cnp)
	if err != nil {
		return cnpReply, err
	}
	return nil, nil
}
