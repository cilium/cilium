// Copyright 2018-2019 Authors of Cilium
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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy/groups"

	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

func init() {
	runtime.ErrorHandlers = []func(error){
		k8s.K8sErrorHandler,
	}
}

func enableCNPWatcher() error {
	log.Info("Starting to garbage collect stale CiliumNetworkPolicy status field entries...")

	_, ciliumV2Controller := informer.NewInformer(
		cache.NewListWatchFromClient(k8s.CiliumClient().CiliumV2().RESTClient(),
			"ciliumnetworkpolicies", v1.NamespaceAll, fields.Everything()),
		&cilium_v2.CiliumNetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				metrics.EventTSK8s.SetToCurrentTime()
				if cnp := k8s.CopyObjToV2CNP(obj); cnp != nil {
					groups.AddDerivativeCNPIfNeeded(cnp.CiliumNetworkPolicy)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				metrics.EventTSK8s.SetToCurrentTime()
				if oldCNP := k8s.CopyObjToV2CNP(oldObj); oldCNP != nil {
					if newCNP := k8s.CopyObjToV2CNP(newObj); newCNP != nil {
						if k8s.EqualV2CNP(oldCNP, newCNP) {
							return
						}

						groups.UpdateDerivativeCNPIfNeeded(newCNP.CiliumNetworkPolicy, oldCNP.CiliumNetworkPolicy)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				metrics.EventTSK8s.SetToCurrentTime()
				cnp := k8s.CopyObjToV2CNP(obj)
				if cnp == nil {
					deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
					if !ok {
						return
					}
					// Delete was not observed by the watcher but is
					// removed from kube-apiserver. This is the last
					// known state and the object no longer exists.
					cnp = k8s.CopyObjToV2CNP(deletedObj.Obj)
					if cnp == nil {
						return
					}
				}
				// The derivative policy will be deleted by the parent but need
				// to delete the cnp from the pooling.
				groups.DeleteDerivativeFromCache(cnp.CiliumNetworkPolicy)

				controllers.RemoveController(fmt.Sprintf("%s/%s", cnp.Namespace, cnp.Name))
			},
		},
		k8s.ConvertToCNP,
	)
	go ciliumV2Controller.Run(wait.NeverStop)

	controller.NewManager().UpdateController("cnp-to-groups",
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				groups.UpdateCNPInformation()
				return nil
			},
			RunInterval: 5 * time.Minute,
		})

	return nil
}

type CNPStatusEventManager struct {
	mutex    lock.RWMutex
	eventMap map[string]chan *NodeStatusUpdate
}

type NodeStatusUpdate struct {
	node string
	*cilium_v2.CiliumNetworkPolicyNodeStatus
}

var controllers = controller.NewManager()

func extractFieldsFromKey(key string) (namespace, name, node string, err error) {
	withoutPrefix := strings.TrimLeft(key, k8s.CNPStatusesPath)
	// result is now namespace/name/node
	splitStr := strings.Split(withoutPrefix, "/")
	if len(splitStr) != 3 {
		err = fmt.Errorf("could not parse key: %s", key)
		return
	}
	return splitStr[0], splitStr[1], splitStr[2], nil

}

func watchForCNPStatusEvents() {
	if !kvstoreEnabled() {
		log.Info("kvstore disabled, not watching for CNPStatus events from kvstore")
		return
	}

	mgr := &CNPStatusEventManager{
		eventMap: make(map[string]chan *NodeStatusUpdate),
	}

restart:
	log.Info("starting kvstore watcher for CNP NodeStatus events")
	watcher := kvstore.Client().ListAndWatch("cnpStatusWatcher", k8s.CNPStatusesPath, 512)
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				log.Debugf("%s closed, restarting watch", watcher.String())
				time.Sleep(500 * time.Millisecond)
				goto restart
			}

			switch event.Typ {
			// Deletion from the kvstore of node statuses is performed by
			// each cilium-agent.
			case kvstore.EventTypeListDone, kvstore.EventTypeDelete:
			case kvstore.EventTypeCreate, kvstore.EventTypeModify:
				var cnpStatusUpdate cilium_v2.CiliumNetworkPolicyNodeStatus
				err := json.Unmarshal(event.Value, &cnpStatusUpdate)
				if err != nil {
					log.WithFields(logrus.Fields{"kvstore-event": event.Typ.String(), "key": event.Key}).
						WithError(err).Error("Not updating CNP Status; error unmarshaling data from key-value store")
					continue
				}

				namespace, name, node, err := extractFieldsFromKey(event.Key)
				if err != nil {
					log.WithFields(logrus.Fields{"kvstore-event": event.Typ.String(), "key": event.Key}).
						WithError(err).Error("Not updating CNP Status; error extracting fields from key")
					continue
				}

				log.WithFields(logrus.Fields{
					"name":      name,
					"namespace": namespace,
					"node":      node,
					"key":       event.Key,
					"type":      event.Typ,
				}).Debug("received event from kvstore")

				nameNamespace := fmt.Sprintf("%s/%s", namespace, name)
				mgr.mutex.Lock()
				ch, ok := mgr.eventMap[nameNamespace]
				if !ok {
					ch = make(chan *NodeStatusUpdate, 512)
					mgr.eventMap[nameNamespace] = ch
					mgr.mutex.Unlock()
					nodeStatusMap := make(map[string]cilium_v2.CiliumNetworkPolicyNodeStatus)
					controllers.UpdateController(nameNamespace, controller.ControllerParams{
						DoFunc: func(ctx context.Context) error {
						Loop:
							for {
								select {
								case <-ctx.Done():
									// Controller was stopped, we can simply exit.
									return nil
								case ev, ok := <-ch:
									if ok {
										nodeStatusMap[ev.node] = *ev.CiliumNetworkPolicyNodeStatus
									}
								default:
									break Loop
								}
							}

							if len(nodeStatusMap) == 0 {
								return nil
							}

							// Now that we have collected all events for
							// the given CNP, update the status for all nodes
							// which have sent us updates.
							if err := k8s.UpdateStatusesByCapabilities(k8s.CiliumClient(), k8sversion.Capabilities(), nil, namespace, name, nodeStatusMap); err != nil {
								return err
							}

							return nil
						},
						RunInterval: time.Second * 10,
						StopFunc: func(ctx context.Context) error {
							close(ch)
							mgr.mutex.Lock()
							delete(mgr.eventMap, nameNamespace)
							mgr.mutex.Unlock()
							return nil
						},
					})
				} else {
					mgr.mutex.Unlock()
				}
				nsu := &NodeStatusUpdate{node: node}
				nsu.CiliumNetworkPolicyNodeStatus = &cnpStatusUpdate

				// TODO - the channel may block once full, which means that
				// we would potentially block for up to 10 seconds (run of the
				// controller) before consuming the next event.
				ch <- nsu
			}
		}
	}
}
