package redirectpolicies

import (
	"context"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/controlplane/servicemanager"
	"github.com/cilium/cilium/pkg/hive"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

type serviceKey = resource.Key

var Cell = cell.Module(
	"redirect-policies",
	"Manages redirect policies based on CiliumLocalRedirectPolicy CRDs",

	cell.Provide(
		newLRPHandler,
		newGetLRPHandler,
	),
)

type lrpHandlerParams struct {
	cell.In

	ServiceManager   servicemanager.ServiceManager
	Log              logrus.FieldLogger
	RedirectPolicies resource.Resource[*cilium_v2.CiliumLocalRedirectPolicy]
	Services         resource.Resource[*slim_corev1.Service]
	Pods             resource.Resource[*slim_corev1.Pod]
}

// TODO rename to redirectPoliciesManager?
type lrpHandler struct {
	params lrpHandlerParams

	log logrus.FieldLogger

	handle servicemanager.ServiceHandle

	podTracker resource.ObjectTracker[*slim_corev1.Pod]

	// Stores mapping of all the current redirect policy frontend to their
	// respective policies
	// Frontends are namespace agnostic
	policyFrontendsByHash map[string]policyID
	// Stores mapping of pods to redirect policies that select the pods
	policyPods map[podID][]policyID
	// Stores redirect policy configs indexed by policyID
	policyConfigs map[policyID]*LRPConfig

	getRequests chan chan []*models.LRPSpec
}

func newLRPHandler(log logrus.FieldLogger, lc hive.Lifecycle, p lrpHandlerParams) *lrpHandler {
	if p.Services == nil {
		log.Info("K8s not available, not registering handler for redirect policies")
		return nil
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	handler := &lrpHandler{
		params:     p,
		log:        p.Log,
		handle:     p.ServiceManager.NewHandle("redirect-policies"),
		podTracker: p.Pods.Tracker(ctx),
	}

	lc.Append(
		hive.Hook{
			OnStart: func(hive.HookContext) error {
				wg.Add(1)
				go func() {
					defer wg.Done()
					handler.processLoop(ctx)
				}()
				return nil
			},
			OnStop: func(hive.HookContext) error {
				cancel()
				wg.Wait()
				return nil
			},
		})

	return handler
}

func (h *lrpHandler) getLRPs() []*models.LRPSpec {
	specs := make(chan []*models.LRPSpec, 1)
	defer close(specs)
	h.getRequests <- specs
	return <-specs
}

func buffer[T any](in <-chan T, d time.Duration) <-chan []T {
	out := make(chan []T)
	go func() {
		// Create a stopped timer. It will start running when an item
		// is added to the buffer.
		timer := time.NewTimer(d)
		if !timer.Stop() {
			<-timer.C
		}

		buf := []T{}

	loop:
		for {
			select {
			case x, ok := <-in:
				if !ok {
					break loop
				}
				if len(buf) == 0 {
					// First item added, start the timer for
					// draining the buffer.
					timer.Reset(d)
				}
				buf = append(buf, x)
			case <-timer.C:
				if len(buf) > 0 {
					out <- buf
					buf = []T{}
				}
			}
		}
		if !timer.Stop() {
			<-timer.C
		}
		if len(buf) > 0 {
			out <- buf
		}
		close(out)
	}()
	return out
}

func (h *lrpHandler) processLoop(ctx context.Context) {
	policies := h.params.RedirectPolicies.Events(ctx)
	pods := buffer(h.podTracker.Events(), time.Second)

	for {
		select {
		case <-ctx.Done():
			return

		case ev := <-policies:
			switch ev.Kind {
			case resource.Sync:
				// FIXME mark handle as synced after policies
				// have been applied to datapath. SWG since we
				// need to wait for the referenced service to show up?
				h.log.Info("Redirect policies now synced")
			case resource.Upsert:
				if _, ok := h.policyConfigs[ev.Key]; ok {
					h.log.Warn("Local redirect policy updates are not handled")
					break
				}
				config, err := Parse(ev.Object, true)
				if err != nil {
					// Probably no point in retrying. Update
					// CiliumLocalRedirectPolicyStatus instead?
					panic("TODO error")
				}
				h.addPolicy(config)

			case resource.Delete:
				h.deletePolicy(ev.Key)
			}
			ev.Done(nil)

		case events := <-pods:
			// TODO: Hmmm, with ObjectTracker we kind of want the sync event for each
			// thing we've started tracking. Not clear how we'd do that with TrackBy()
			// though, unless we associate some user-defined identifiers/data. Though
			// maybe this buffering is reasonable enough?
			for _, ev := range events {
				ev.Done(nil)
			}
			/*
				if ev.Kind != resource.Sync {
					h.log.Infof("Got pods event for %s", ev.Key)
				}
				ev.Done(nil)*/

		case out := <-h.getRequests:
			list := make([]*models.LRPSpec, 0, len(h.policyConfigs))
			for _, v := range h.policyConfigs {
				list = append(list, v.GetModel())
			}
			out <- list

		}
	}
}

func (h *lrpHandler) addPolicy(config *LRPConfig) {
	// Start tracking the local pods that match the backend selector.
	config.podUntrack = h.podTracker.TrackBy(config.policyConfigSelectsPod)

	// Create the frontend. The backends will be filled in once matching pods
	// appear.
	if config.lrpType == lrpConfigTypeSvc {
		var fe loadbalancer.FELocalRedirectService
		fe.Name = loadbalancer.ServiceName{
			Scope:     loadbalancer.ScopeSVC,
			Name:      config.serviceID.Name,
			Namespace: config.serviceID.Namespace,
		}
		config.frontend = fe
	}

	h.policyConfigs[config.key] = config
}

func (h *lrpHandler) deletePolicy(id policyID) {
	config, ok := h.policyConfigs[id]
	if !ok {
		panic("TODO deletePolicy, but no policy found")
		return
	}
	// Stop tracking the pods matching the backend selector.
	config.podUntrack()
	// TODO h.handle.DeleteFrontend

	delete(h.policyConfigs, id)
}

func flatten[E any](xs [][]E) []E {
	out := []E{}
	for i := range xs {
		for j := range xs[i] {
			out = append(out, xs[i][j])
		}
	}
	return out
}

func drain[T any](ch <-chan T) {
	for range ch {
	}
}
