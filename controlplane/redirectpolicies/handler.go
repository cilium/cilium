package redirectpolicies

import (
	"context"
	"sync"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/controlplane/servicemanager"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/status"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

type serviceKey = resource.Key

var Cell = cell.Module(
	"redirect-policies",
	"Manages local redirect policies based on CiliumLocalRedirectPolicy CRDs",

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
	Reporter         status.Reporter
}

// TODO rename to redirectPoliciesManager?
type lrpHandler struct {
	params        lrpHandlerParams
	log           logrus.FieldLogger
	handle        servicemanager.ServiceHandle
	podTracker    resource.ObjectTracker[*slim_corev1.Pod]
	policyConfigs map[resource.Key]*LRPConfig
	getRequests   chan chan []*models.LRPSpec
}

func newLRPHandler(log logrus.FieldLogger, lc hive.Lifecycle, p lrpHandlerParams) *lrpHandler {
	if p.Services == nil {
		p.Reporter.Down("Kubernetes not enabled")
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

func (h *lrpHandler) processLoop(ctx context.Context) {
	policies := h.params.RedirectPolicies.Events(ctx)
	pods := h.podTracker.Events()

	h.params.Reporter.OK()
	defer h.params.Reporter.Down("Stopped")

	for {
		select {
		case <-ctx.Done():
			return

		case ev := <-policies:
			switch ev.Kind {
			case resource.Sync:
				// TODO: Would want to wait for pods? With ObjectTracker
				// we don't get sync events per pod. Need another way.
				h.handle.Synchronized()
			case resource.Upsert:
				config, err := Parse(ev.Object, true)
				if err != nil {
					// Probably no point in retrying. Update
					// CiliumLocalRedirectPolicy.Status instead?
					panic("TODO error")
				}
				h.upsertPolicy(ev.Key, config)

			case resource.Delete:
				h.deletePolicy(ev.Key)
			}
			ev.Done(nil)

		case ev := <-pods:
			// TODO: if we match on multiple pods we'll end up with many calls to
			// datapath. Should we buffer here or leave that to lower layers?
			switch ev.Kind {
			case resource.Upsert:
				h.upsertPod(ev.Key, ev.Object)
			case resource.Delete:
				h.deletePod(ev.Key)
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

func applyLRPConfig(h servicemanager.ServiceHandle, c *LRPConfig) {
	redirectConfig := servicemanager.LocalRedirectConfig{}
	for _, feM := range c.frontendMappings {
		redirectConfig.FrontendPorts = append(
			redirectConfig.FrontendPorts,
			feM.feAddr.L4Addr.Port)
	}
	redirectConfig.LocalBackends = flatten(maps.Values(c.podBackends)) // TODO efficiency
	name := lb.ServiceName{Authority: lb.AuthoritySVC, Name: c.serviceID.Name, Namespace: c.serviceID.Namespace}
	h.SetLocalRedirects(name, redirectConfig)
}

// upsertPod looks up matching policies and updates the matching pod backends
// in the config.
// TODO: Why are we looking at pods at all and not the local endpoints???
func (h *lrpHandler) upsertPod(key resource.Key, pod *slim_corev1.Pod) {
	if k8sUtils.GetLatestPodReadiness(pod.Status) != slim_corev1.ConditionTrue {
		return
	}

	podIPs := k8sUtils.ValidIPs(pod.Status)
	podAddrs := make([]cmtypes.AddrCluster, 0, len(podIPs))
	for _, podIP := range podIPs {
		addr, err := cmtypes.ParseAddrCluster(podIP)
		if err != nil {
			// TODO: This needs to be reported somehow.
			continue
		}
		podAddrs = append(podAddrs, addr)
	}
	if len(podAddrs) == 0 {
		return
	}

	for _, c := range h.policyConfigs {
		if c.checkNamespace(pod.Namespace) && c.policyConfigSelectsPod(pod) {
			h.updateConfigForPod(c, key, pod, podAddrs)
			break
		}
	}
}

func (h *lrpHandler) updateConfigForPod(config *LRPConfig, key resource.Key, pod *slim_corev1.Pod, podAddrs []cmtypes.AddrCluster) {
	var podBackends []*lb.Backend
	for _, podAddr := range podAddrs {
		for _, container := range pod.Spec.Containers {
			for _, port := range container.Ports {
				if port.Name == "" {
					continue
				}
				l4type, err := lb.NewL4Type(string(port.Protocol))
				if err != nil {
					continue
				}
				l4addr := lb.L4Addr{Protocol: l4type, Port: uint16(port.ContainerPort)}

				// If backend ports were specified, check if this is a match.
				if len(config.backendPorts) > 0 {
					match := false
					for _, bePort := range config.backendPorts {
						if bePort.name != "" && bePort.name != port.Name {
							continue
						}
						if bePort.l4Addr.DeepEqual(&l4addr) {
							match = true
							break
						}
					}
					if !match {
						continue
					}
				}
				l3n4 := lb.L3n4Addr{AddrCluster: podAddr, L4Addr: l4addr}
				podBackends = append(podBackends, &lb.Backend{FEPortName: port.Name, L3n4Addr: l3n4})
			}
		}
	}

	config.podBackends[key] = podBackends
	applyLRPConfig(h.handle, config)
}

func (h *lrpHandler) deletePod(key resource.Key) {
	// TODO efficiency
	for _, c := range h.policyConfigs {
		if _, ok := c.podBackends[key]; ok {
			delete(c.podBackends, key)
			applyLRPConfig(h.handle, c)
		}
	}
}

func (h *lrpHandler) upsertPolicy(key resource.Key, config *LRPConfig) {
	if config.lrpType != lrpConfigTypeSvc {
		panic("TODO other lrp config types")
		// For the address one the difference is that we'll use a different
		// scope (lb.ScopeLRP) and we don't call SetLocalRedirects but rather
		// upsert a FELocalRedirectAddress.
	}

	// Start tracking the local pods that match the backend selector.
	// TODO: Use a single efficient TrackBy function. This does not scale!
	// We could have a "loose" match on pods, e.g. by namespace and then
	// do label-based matching by iterating over configs.
	config.podUntrack = h.podTracker.TrackBy(config.policyConfigSelectsPod)
	h.policyConfigs[key] = config
}

func (h *lrpHandler) deletePolicy(id policyID) {
	config, ok := h.policyConfigs[id]
	if !ok {
		panic("TODO deletePolicy, but no policy found")
	}
	config.podUntrack()
	delete(h.policyConfigs, id)
	name := lb.ServiceName{Authority: lb.AuthoritySVC, Name: config.serviceID.Name, Namespace: config.serviceID.Namespace}

	// FIXME: might have multiple policies targeting same service name
	h.handle.RemoveLocalRedirects(name)
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
