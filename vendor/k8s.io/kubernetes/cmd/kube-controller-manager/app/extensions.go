/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package app implements a server that runs a set of active
// components.  This includes replication controllers, service endpoints and
// nodes.
//
package app

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kubernetes/pkg/controller/daemon"
	"k8s.io/kubernetes/pkg/controller/deployment"
	"k8s.io/kubernetes/pkg/controller/replicaset"
)

func startDaemonSetController(ctx ControllerContext) (bool, error) {
	if !ctx.AvailableResources[schema.GroupVersionResource{Group: "extensions", Version: "v1beta1", Resource: "daemonsets"}] {
		return false, nil
	}
	go daemon.NewDaemonSetsController(
		ctx.InformerFactory.Extensions().V1beta1().DaemonSets(),
		ctx.InformerFactory.Apps().V1beta1().ControllerRevisions(),
		ctx.InformerFactory.Core().V1().Pods(),
		ctx.InformerFactory.Core().V1().Nodes(),
		ctx.ClientBuilder.ClientOrDie("daemon-set-controller"),
	).Run(int(ctx.Options.ConcurrentDaemonSetSyncs), ctx.Stop)
	return true, nil
}

func startDeploymentController(ctx ControllerContext) (bool, error) {
	if !ctx.AvailableResources[schema.GroupVersionResource{Group: "extensions", Version: "v1beta1", Resource: "deployments"}] {
		return false, nil
	}
	go deployment.NewDeploymentController(
		ctx.InformerFactory.Extensions().V1beta1().Deployments(),
		ctx.InformerFactory.Extensions().V1beta1().ReplicaSets(),
		ctx.InformerFactory.Core().V1().Pods(),
		ctx.ClientBuilder.ClientOrDie("deployment-controller"),
	).Run(int(ctx.Options.ConcurrentDeploymentSyncs), ctx.Stop)
	return true, nil
}

func startReplicaSetController(ctx ControllerContext) (bool, error) {
	if !ctx.AvailableResources[schema.GroupVersionResource{Group: "extensions", Version: "v1beta1", Resource: "replicasets"}] {
		return false, nil
	}
	go replicaset.NewReplicaSetController(
		ctx.InformerFactory.Extensions().V1beta1().ReplicaSets(),
		ctx.InformerFactory.Core().V1().Pods(),
		ctx.ClientBuilder.ClientOrDie("replicaset-controller"),
		replicaset.BurstReplicas,
	).Run(int(ctx.Options.ConcurrentRSSyncs), ctx.Stop)
	return true, nil
}
