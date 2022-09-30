package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"go.uber.org/fx"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/stream"
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
		viper.GetViper(), pflag.CommandLine,

		client.Cell,
		resourcesCell,
		printServicesCell,

		hive.Require[*PrintServices](),
	)
	pflag.Parse()
	hive.Run()
}

var resourcesCell = hive.NewCell(
	"resources",
	fx.Provide(
		resource.NewResourceConstructor[*corev1.Pod](
			func(c client.Clientset) cache.ListerWatcher {
				return utils.ListerWatcherFromTyped[*corev1.PodList](c.CoreV1().Pods(""))
			},
		),
		resource.NewResourceConstructor[*corev1.Service](
			func(c client.Clientset) cache.ListerWatcher {
				return utils.ListerWatcherFromTyped[*corev1.ServiceList](c.CoreV1().Services(""))
			},
		),
	),
)

var printServicesCell = hive.NewCell(
	"print-services",
	fx.Provide(newPrintServices),
)

type PrintServices struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	pods     resource.Resource[*corev1.Pod]
	services resource.Resource[*corev1.Service]
}

type printServicesParams struct {
	fx.In

	Lifecycle fx.Lifecycle
	Pods      resource.Resource[*corev1.Pod]
	Services  resource.Resource[*corev1.Service]
}

func newPrintServices(p printServicesParams) (*PrintServices, error) {
	if p.Pods == nil || p.Services == nil {
		return nil, fmt.Errorf("Resources not available. Missing --k8s-kubeconfig-path?")
	}
	ctx, cancel := context.WithCancel(context.Background())
	ps := &PrintServices{
		ctx:      ctx,
		cancel:   cancel,
		pods:     p.Pods,
		services: p.Services,
	}
	p.Lifecycle.Append(fx.Hook{OnStart: ps.start, OnStop: ps.stop})
	return ps, nil
}

func (ps *PrintServices) start(context.Context) error {
	ps.wg.Add(1)

	ps.printServices()
	go ps.run()

	return nil
}

func (ps *PrintServices) stop(context.Context) error {
	ps.cancel()
	ps.wg.Wait()
	return nil
}

// printServices prints services at start to show how Store() can be used.
func (ps *PrintServices) printServices() {

	// Retrieve a handle to the store. Blocks until the store has synced.
	// Can fail if the context is cancelled (e.g. PrintServices is being stopped).
	store, err := ps.services.Store(ps.ctx)
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

func (ps *PrintServices) run() {
	defer ps.wg.Done()

	// Always restart unless we're being stopped.
	for ps.ctx.Err() == nil {
		log.Info("Starting to print periodic updates to service to pod mappings")
		ps.processLoop()
	}
}

// processLoop observes changes to pods and services and periodically prints the
// services and the pods that each service selects.
func (ps *PrintServices) processLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	// Subscribe to pods and services. Use a shared channel for errors
	// and make it buffered so unsubscribing from the resource does not get
	// blocked.
	errs := make(chan error, 2)
	pods := stream.ToChannel[resource.Event[*corev1.Pod]](ps.ctx, errs, ps.pods)
	services := stream.ToChannel[resource.Event[*corev1.Service]](ps.ctx, errs, ps.services)

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

			// Event can be handled synchronously with 'Handle()':
			ev.Handle(
				func(store resource.Store[*corev1.Pod]) error {
					log.Infof("Pods synced (%d pods)", len(store.List()))
					return nil
				},
				func(k resource.Key, pod *corev1.Pod) error {
					log.Infof("Pod %s updated", k)
					podLabels[k] = labels.Map2Labels(pod.Labels, "k8s")
					return nil
				},
				func(k resource.Key, deletedPod *corev1.Pod) error {
					log.Infof("Pod %s deleted", k)
					delete(podLabels, k)
					return nil
				},
			)

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

			// Event can also be handled with a type switch and call to 'Done()'
			// (which allows parallel processing of events):
			switch ev := ev.(type) {
			case *resource.SyncEvent[*corev1.Service]:
				log.Infof("Services synced (%d services)", len(ev.Store.List()))
			case *resource.UpdateEvent[*corev1.Service]:
				log.Infof("Service %s updated", ev.Key)
				if len(ev.Object.Spec.Selector) > 0 {
					serviceSelectors[ev.Key] = labels.Map2Labels(ev.Object.Spec.Selector, "k8s")
				}
			case *resource.DeleteEvent[*corev1.Service]:
				log.Infof("Service %s deleted", ev.Key)
				delete(serviceSelectors, ev.Key)
			}
			// We must now call 'Done()' directly. If we would call it with a non-nil
			// error the processing for this object would be retried later, with possible
			// a newer version of the object. If retries fail, the stream would complete
			// with the error.
			ev.Done(nil)
		}
	}

	// Log errors if any
	close(errs)
	for err := range errs {
		if err != nil {
			log.WithError(err).Error("Error occurred processing updates")
		}
	}
}
