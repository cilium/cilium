package redirectpolicies

import (
	"context"
	"sync"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/controlplane/servicemanager"
	"github.com/cilium/cilium/pkg/counter"
	"github.com/cilium/cilium/pkg/hive"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s"
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

	serviceTracker  resource.ObjectTracker[*slim_corev1.Service]
	serviceRefCount counter.Counter[serviceKey]

	handle servicemanager.ServiceHandle

	// Stores mapping of all the current redirect policy frontend to their
	// respective policies
	// Frontends are namespace agnostic
	policyFrontendsByHash map[string]policyID
	// Stores mapping of redirect policy serviceID to the corresponding policyID for
	// easy lookup in policyConfigs
	policyServices map[k8s.ServiceID]policyID
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

	handler := &lrpHandler{
		params:          p,
		log:             p.Log,
		handle:          p.ServiceManager.NewHandle("redirect-policies"),
		serviceRefCount: make(counter.Counter[serviceKey]),
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	handler.serviceTracker = p.Services.Tracker(ctx)

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

func (h *lrpHandler) processLoop(ctx context.Context) {
	policies := h.params.RedirectPolicies.Events(ctx)
	pods := h.params.Pods.Events(ctx)
	services := h.serviceTracker.Events()

	for {
		select {
		case <-ctx.Done():
			// FIXME: would prefer `defer drain(xs)` but that'll block if there's an exception
			// and context isn't actually cancelled. Otoh, maybe wrap ctx and defer cancel?
			drain(services)
			drain(policies)
			drain(pods)
			return

		case ev := <-policies:
			switch ev.Kind {
			case resource.Sync:
				// FIXME mark handle as synced after policies
				// have been applied to datapath. SWG since we
				// need to wait for the referenced service to show up?
				h.log.Info("Redirect policies now synced")
			case resource.Upsert:
				config, err := Parse(ev.Object, true)
				if err != nil {
					// Probably no point in retrying. Update
					// CiliumLocalRedirectPolicyStatus instead?
					panic("TODO error")
				}
				h.updatePolicy(config)

			case resource.Delete:
				h.deletePolicy(ev.Key)
			}
			ev.Done(nil)

		case ev := <-pods:
			if ev.Kind != resource.Sync {
				h.log.Infof("Got pods event for %s", ev.Key)
			}
			ev.Done(nil)

		case ev := <-services:
			switch ev.Kind {
			case resource.Upsert:
				h.updateService(ev.Key, ev.Object)
			case resource.Delete:
				h.deleteService(ev.Key, ev.Object)
			}
			ev.Done(nil)

		case out := <-h.getRequests:
			list := make([]*models.LRPSpec, 0, len(h.policyConfigs))
			for _, v := range h.policyConfigs {
				list = append(list, v.GetModel())
			}
			out <- list

		}
	}
}

func (h *lrpHandler) updateService(key resource.Key, svc *slim_corev1.Service) {
	panic("TBD")
}

func (h *lrpHandler) deleteService(key resource.Key, svc *slim_corev1.Service) {
	panic("TBD")
}

func (h *lrpHandler) updatePolicy(config *LRPConfig) {
	if config.lrpType == lrpConfigTypeSvc {
		if h.serviceRefCount.Add(*config.serviceID) {
			// First to be interested in this service
			// -> start tracking it.
			h.serviceTracker.Track(*config.serviceID)
		}
	}
	panic("TBD")
}

func (h *lrpHandler) deletePolicy(id policyID) {
	panic("TBD")
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
