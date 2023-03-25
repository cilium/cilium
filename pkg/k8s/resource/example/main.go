// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/cilium/workerpool"
	"github.com/spf13/pflag"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// PrintServices for the pkg/k8s/resource which observers pods and services and once a second prints the list of
// services with the pods associated with each service.
//
// Run with:
//
//  go run . --k8s-kubeconfig-path ~/.kube/config
//
// To test, try running:
//
//  kubectl run -it --rm --image=nginx  --port=80 --expose nginx

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "example")
)

func main() {
	hive := hive.New(
		client.Cell,
		resourcesCell,
		printServicesCell,

		cell.Invoke(func(*PrintServices) {}),
	)
	hive.RegisterFlags(pflag.CommandLine)
	pflag.Parse()
	hive.Run()
}

var resourcesCell = cell.Module(
	"resources",
	"Kubernetes Pod and Service resources",

	cell.Provide(
		func(lc hive.Lifecycle, c client.Clientset) resource.Resource[*corev1.Pod] {
			if !c.IsEnabled() {
				return nil
			}
			lw := utils.ListerWatcherFromTyped[*corev1.PodList](c.CoreV1().Pods(""))
			return resource.New[*corev1.Pod](lc, lw)
		},
		func(lc hive.Lifecycle, c client.Clientset) resource.Resource[*corev1.Service] {
			if !c.IsEnabled() {
				return nil
			}
			lw := utils.ListerWatcherFromTyped[*corev1.ServiceList](c.CoreV1().Services(""))
			return resource.New[*corev1.Service](lc, lw)
		},
	),
)

var printServicesCell = cell.Module(
	"print-services",
	"Prints Kubernetes Services",

	cell.Provide(newPrintServices),
)

type PrintServices struct {
	wp *workerpool.WorkerPool

	pods     resource.Resource[*corev1.Pod]
	services resource.Resource[*corev1.Service]
}

type printServicesParams struct {
	cell.In

	Lifecycle hive.Lifecycle
	Pods      resource.Resource[*corev1.Pod]
	Services  resource.Resource[*corev1.Service]
}

func newPrintServices(p printServicesParams) (*PrintServices, error) {
	if p.Pods == nil || p.Services == nil {
		return nil, fmt.Errorf("Resources not available. Missing --k8s-kubeconfig-path?")
	}
	ps := &PrintServices{
		pods:     p.Pods,
		services: p.Services,
	}
	p.Lifecycle.Append(ps)
	return ps, nil
}

func (ps *PrintServices) Start(startCtx hive.HookContext) error {
	ps.wp = workerpool.New(1)
	ps.wp.Submit("processLoop", ps.processLoop)

	// Using the start context, do a blocking dump of all
	// services. Using the start context here makes sure that
	// this operation is aborted if it blocks too long.
	ps.printServices(startCtx)

	return nil
}

func (ps *PrintServices) Stop(hive.HookContext) error {
	ps.wp.Close()
	return nil
}

// printServices prints services at start to show how Store() can be used.
func (ps *PrintServices) printServices(ctx context.Context) {

	// Retrieve a handle to the store. Blocks until the store has synced.
	// Can fail if the context is cancelled (e.g. PrintServices is being stopped).
	store, err := ps.services.Store(ctx)
	if err != nil {
		log.Errorf("Failed to retrieve store: %s, aborting", err)
		return
	}

	log.Info("Services:")
	for _, svc := range store.List() {
		labels := labels.Map2Labels(svc.Spec.Selector, "k8s")
		log.Infof("  - %s/%s\ttype=%s\tselector=%s", svc.Namespace, svc.Name, svc.Spec.Type, labels)
	}

}

// processLoop observes changes to pods and services and periodically prints the
// services and the pods that each service selects.
func (ps *PrintServices) processLoop(ctx context.Context) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	// Subscribe to pods and services.
	pods := ps.pods.Events(ctx)
	services := ps.services.Events(ctx)

	// State:
	podLabels := make(map[resource.Key]labels.Labels)
	serviceSelectors := make(map[resource.Key]labels.Labels)

	// Process the pod and service events and periodically print the services.
	// Loop until the pods and services have completed. We need to process
	// both streams to the end to make sure we're not blocking the resource even
	// if we're stopping (e.g. context cancelled).
	for pods != nil || services != nil {
		select {
		case <-ticker.C:
			for key, selectors := range serviceSelectors {
				log.Infof("%s (%s)", key, selectors)
				for podName, lbls := range podLabels {
					match := true
					for _, sel := range selectors {
						match = match && lbls.Has(sel)
					}
					if match {
						log.Infof("  - %s", podName)
					}
				}
			}
			log.Println("----------------------------------------------------------")

		case ev, ok := <-pods:
			if !ok {
				pods = nil
				continue
			}

			switch ev.Kind {
			case resource.Sync:
				// Pods have now been synced and the set of Upsert events
				// received thus far forms a coherent snapshot of the pods
				// at a specific point in time. This is usually used in the context
				// of garbage collection at startup: we now know what is the set of pods that
				// existed at the api-server brief moment ago and can remove persisted
				// data of pods that are not part of this set.
			case resource.Upsert:
				log.Infof("Pod %s updated", ev.Key)
				podLabels[ev.Key] = labels.Map2Labels(ev.Object.Labels, "k8s")
			case resource.Delete:
				log.Infof("Pod %s deleted", ev.Key)
				delete(podLabels, ev.Key)
			}

			// Always mark the event as processed. This tells the resource that more
			// events can be now emitted for this key and if error is nil it clears
			// any rate limiting state related to failed attempts.
			ev.Done(nil)

		case ev, ok := <-services:
			if !ok {
				services = nil
				continue
			}

			// Simulate a fault 10% of the time. This will cause this event to be retried
			// later.
			if rand.Intn(10) == 1 {
				log.Info("Injecting a fault!")
				ev.Done(errors.New("injected fault"))
				continue
			}

			switch ev.Kind {
			case resource.Sync:
				log.Info("Services synced")
			case resource.Upsert:
				log.Infof("Service %s updated", ev.Key)
				if len(ev.Object.Spec.Selector) > 0 {
					serviceSelectors[ev.Key] = labels.Map2Labels(ev.Object.Spec.Selector, "k8s")
				}
			case resource.Delete:
				log.Infof("Service %s deleted", ev.Key)
				delete(serviceSelectors, ev.Key)
			}
			ev.Done(nil)
		}
	}

	return nil
}
