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
	"k8s.io/kubernetes/pkg/controller/cronjob"
	"k8s.io/kubernetes/pkg/controller/job"
)

func startJobController(ctx ControllerContext) (bool, error) {
	if !ctx.AvailableResources[schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}] {
		return false, nil
	}
	go job.NewJobController(
		ctx.InformerFactory.Core().V1().Pods(),
		ctx.InformerFactory.Batch().V1().Jobs(),
		ctx.ClientBuilder.ClientOrDie("job-controller"),
	).Run(int(ctx.Options.ConcurrentJobSyncs), ctx.Stop)
	return true, nil
}

func startCronJobController(ctx ControllerContext) (bool, error) {
	if !ctx.AvailableResources[schema.GroupVersionResource{Group: "batch", Version: "v1beta1", Resource: "cronjobs"}] {
		return false, nil
	}
	go cronjob.NewCronJobController(
		ctx.ClientBuilder.ClientOrDie("cronjob-controller"),
	).Run(ctx.Stop)
	return true, nil
}
