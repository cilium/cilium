//  Copyright 2021 Authors of Cilium
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package watchers

import (
	"time"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/metrics"

	"github.com/sirupsen/logrus"
)

type cebSubscriber struct {
	kWatcher *K8sWatcher
}

func newCEBSubscriber(k *K8sWatcher) *cebSubscriber {
	return &cebSubscriber{
		kWatcher: k,
	}
}

// OnAdd invoked for newly created CEBs, iterates over coreCEPs
// packed in the CEB, converts coreCEP into types.CEP and calls endpointUpdated only for remoteNode CEPs.
func (cs *cebSubscriber) OnAdd(ceb *cilium_v2a1.CiliumEndpointBatch) {
	for i, ep := range ceb.Endpoints {
		log.WithFields(logrus.Fields{
			"CEBName": ceb.GetName(),
			"CEPName": ep.Name,
		}).Debug("CEB added, calling CoreEndpointUpdate")
		c := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(&ceb.Endpoints[i], ceb.Namespace)
		// LocalNode already has the latest CEP.
		// Hence, skip processing endpointupdate for localNode CEPs.
		if p := cs.kWatcher.endpointManager.LookupPodName(k8sUtils.GetObjNamespaceName(c)); p != nil {
			timeSinceCepCreated := time.Since(p.GetCreatedAt())
			metrics.EndpointPropagationDelay.WithLabelValues().Observe(timeSinceCepCreated.Seconds())
			continue
		}
		cs.kWatcher.endpointUpdated(nil, c)
	}
}

// OnUpdate invoked for modified CEBs, it compares old CEB and new CEB objects
// determines below things
// 1) any coreCEPs are removed from CEB
// 2) any new coreCEPs are packed in CEB
// 3) any existing coreCEPs are modified in CEB
// call endpointUpdated/endpointDeleted only for remote node CEPs.
func (cs *cebSubscriber) OnUpdate(oldCEB, newCEB *cilium_v2a1.CiliumEndpointBatch) {
	oldCEPs := make(map[string]*cilium_v2a1.CoreCiliumEndpoint, len(oldCEB.Endpoints))
	for i, ep := range oldCEB.Endpoints {
		oldCEPs[oldCEB.Namespace+"/"+ep.Name] = &oldCEB.Endpoints[i]
	}

	newCEPs := make(map[string]*cilium_v2a1.CoreCiliumEndpoint, len(newCEB.Endpoints))
	for i, ep := range newCEB.Endpoints {
		newCEPs[newCEB.Namespace+"/"+ep.Name] = &newCEB.Endpoints[i]
	}

	// Handle, removed CEPs from the CEB.
	// old CEB would have one or more stale cep entries, remove stale CEPs from oldCEB.
	for CEPName, oldCEP := range oldCEPs {
		if _, exists := newCEPs[CEPName]; !exists {
			log.WithFields(logrus.Fields{
				"CEBName": oldCEB.GetName(),
				"CEPName": CEPName,
			}).Debug("CEP deleted, calling endpointDeleted")
			c := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(oldCEP, oldCEB.Namespace)
			// LocalNode already has the latest CEP.
			// Hence, skip processing endpointupdate for localNode CEPs.
			if p := cs.kWatcher.endpointManager.LookupPodName(k8sUtils.GetObjNamespaceName(c)); p != nil {
				continue
			}
			cs.kWatcher.endpointDeleted(c)
		}
	}

	// Handle any new CEPs inserted in the CEB.
	for CEPName, newCEP := range newCEPs {
		if _, exists := oldCEPs[CEPName]; !exists {
			log.WithFields(logrus.Fields{
				"CEBName": oldCEB.GetName(),
				"CEPName": CEPName,
			}).Debug("CEP inserted, calling endpointUpdated")
			c := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(newCEP, newCEB.Namespace)
			// LocalNode already has the latest CEP.
			// Hence, skip processing endpointupdate for localNode CEPs.
			if p := cs.kWatcher.endpointManager.LookupPodName(k8sUtils.GetObjNamespaceName(c)); p != nil {
				timeSinceCepCreated := time.Since(p.GetCreatedAt())
				metrics.EndpointPropagationDelay.WithLabelValues().Observe(timeSinceCepCreated.Seconds())
				continue
			}
			cs.kWatcher.endpointUpdated(nil, c)
		}
	}

	// process if any CEP value changed from old to new
	for CEPName, newCEP := range newCEPs {
		if oldCEP, exists := oldCEPs[CEPName]; exists {
			if oldCEP.DeepEqual(newCEP) {
				continue
			}
			log.WithFields(logrus.Fields{
				"CEBName": oldCEB.GetName(),
				"CEPName": CEPName,
			}).Debug("CEB updated, calling endpointUpdated")
			newC := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(newCEP, newCEB.Namespace)
			oldC := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(oldCEP, oldCEB.Namespace)
			// LocalNode already has the latest CEP.
			// Hence, skip processing endpointUpdated for localNode CEPs.
			if p := cs.kWatcher.endpointManager.LookupPodName(k8sUtils.GetObjNamespaceName(newC)); p != nil {
				continue
			}
			cs.kWatcher.endpointUpdated(oldC, newC)
		}
	}
}

// OnDelete invoked for deleted CEBs, iterates over coreCEPs
// and calls endpointDeleted only for remoteNode CEPs.
func (cs *cebSubscriber) OnDelete(ceb *cilium_v2a1.CiliumEndpointBatch) {
	for i, ep := range ceb.Endpoints {
		log.WithFields(logrus.Fields{
			"CEBName": ceb.GetName(),
			"CEPName": ep.Name,
		}).Debug("CEB deleted, calling endpointDeleted")
		c := k8s.ConvertCoreCiliumEndpointToTypesCiliumEndpoint(&ceb.Endpoints[i], ceb.Namespace)
		// LocalNode already deleted the CEP.
		// Hence, skip processing endpointDeleted for localNode CEPs.
		if p := cs.kWatcher.endpointManager.LookupPodName(k8sUtils.GetObjNamespaceName(c)); p != nil {
			continue
		}
		cs.kWatcher.endpointDeleted(c)
	}
}
