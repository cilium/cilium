package envoy

/*

- listen to handle.Events
- on each resource.Event[CiliumEnvoyConfig]
- ... mark that we manage 'serviceID'
- ... handle.UpsertFrontend(serviceID, l7Frontend)
- on service manager event for services we manage: UpsertEnvoyEndpoints

TODO: can we miss an event on restart if events are not emitted when nothing
changes? should we first do a sync to build up the set of "envoy configs", then
subscribe, and then do UpsertFrontend?

or should ServiceHandle have a "ServiceTracker" type thing so we can
subscribe to specific services cheaply?

*/

import (
	"context"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/controlplane/servicemanager"
	"github.com/cilium/cilium/pkg/hive"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/loadbalancer"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

type serviceKey = resource.Key

var EnvoyConfigHandlerCell = cell.Module(
	"envoy-cec-handler",
	"Handles L7 proxy redirection based on CiliumEnvoyConfig CRDs",

	cell.Provide(newCECHandler),
	cell.Invoke(func(*cecHandler) {}),
)

type cecHandlerParams struct {
	cell.In

	ServiceManager servicemanager.ServiceManager
	Log            logrus.FieldLogger
	CECs           resource.Resource[*cilium_v2.CiliumEnvoyConfig]
	CCECs          resource.Resource[*cilium_v2.CiliumClusterwideEnvoyConfig]
	EnvoyCache     EnvoyCache
}

// TODO replace with real thing:
type EnvoyCache interface {
	UpsertEnvoyEndpoints(loadbalancer.ServiceName, map[string][]*loadbalancer.Backend) error
	UpsertEnvoyResources(context.Context, Resources) error
	PortAllocator
}

type cecHandler struct {
	params cecHandlerParams

	log logrus.FieldLogger

	handle         servicemanager.ServiceHandle
	configServices map[resource.Key]container.Set[loadbalancer.ServiceName]
	redirected     map[loadbalancer.ServiceName]*cilium_v2.ServiceListener
}

func newCECHandler(log logrus.FieldLogger, lc hive.Lifecycle, p cecHandlerParams) *cecHandler {
	if p.CECs == nil {
		log.Info("K8s not available, not starting the handler for CiliumEnvoyConfig")
		return nil
	}

	handler := &cecHandler{
		params:         p,
		log:            p.Log,
		handle:         p.ServiceManager.NewHandle("l7proxy"),
		configServices: map[resource.Key]container.Set[loadbalancer.ServiceName]{},
		redirected:     map[loadbalancer.ServiceName]*cilium_v2.ServiceListener{},
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

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

func (h *cecHandler) processLoop(ctx context.Context) {
	cecs := h.params.CECs.Events(ctx)
	ccecs := h.params.CCECs.Events(ctx)
	cecsSynced, ccecsSynced := false, false
	serviceEvents := h.handle.Events()

	for {
		select {
		case <-ctx.Done():
			h.handle.Close()
			return

		case ev := <-serviceEvents:
			_, ok := h.redirected[ev.Name]
			if !ok {
				continue
			}
			backends := map[string][]*loadbalancer.Backend{}
			for i := range ev.Backends {
				be := ev.Backends[i]
				backends[be.FEPortName] = append(backends[be.FEPortName], &be)
			}

			// TODO: context for UpsertEnvoyEndpoints. timeout? use a work queue?
			// should be implemented by proxy/UpsertEnvoyEndpoints.
			h.params.EnvoyCache.UpsertEnvoyEndpoints(ev.Name, backends)

		case ev := <-cecs:
			switch ev.Kind {
			case resource.Sync:
				cecsSynced = true
				if cecsSynced && ccecsSynced {
					h.handle.Synchronized()
				}
			case resource.Upsert:
				h.upsert(ev.Key, &ev.Object.Spec)
			case resource.Delete:
				h.delete(ev.Key, &ev.Object.Spec)
			}
			ev.Done(nil)

		case ev := <-ccecs:
			switch ev.Kind {
			case resource.Sync:
				ccecsSynced = true
				if cecsSynced && ccecsSynced {
					h.handle.Synchronized()
				}
			case resource.Upsert:
				h.upsert(ev.Key, &ev.Object.Spec)
			case resource.Delete:
				h.delete(ev.Key, &ev.Object.Spec)
			}
			ev.Done(nil)
		}
	}
}

func (h *cecHandler) delete(key resource.Key, spec *cilium_v2.CiliumEnvoyConfigSpec) {
	for _, svc := range spec.Services {
		name := loadbalancer.ServiceName{
			Scope:     loadbalancer.ScopeSVC,
			Namespace: svc.Namespace,
			Name:      svc.Name,
		}
		h.handle.RemoveProxyRedirect(name)
		h.handle.Unobserve(name)
	}
	delete(h.configServices, key)
}

func (h *cecHandler) upsert(key resource.Key, spec *cilium_v2.CiliumEnvoyConfigSpec) {
	resources, err := ParseResources(
		key.Namespace,
		key.Name,
		spec.Resources,
		true,
		h.params.EnvoyCache,
	)
	if err != nil {
		fmt.Printf("TODO handle error: bad envoy config: %q", err)
		return
	}

	removedServices := h.configServices[key].Clone()
	h.configServices[key] = container.NewSet[loadbalancer.ServiceName]()
	for _, svc := range spec.Services {
		name := loadbalancer.ServiceName{
			Scope:     loadbalancer.ScopeSVC,
			Namespace: svc.Namespace,
			Name:      svc.Name,
		}
		// Find the listener the service is to be redirected to
		var proxyPort uint16
		for _, l := range resources.Listeners {
			if svc.Listener == "" || l.Name == svc.Listener {
				if addr := l.GetAddress(); addr != nil {
					if sa := addr.GetSocketAddress(); sa != nil {
						proxyPort = uint16(sa.GetPortValue())
					}
				}
			}
		}
		if proxyPort == 0 {
			fmt.Printf("TODO handle error: Listener %q not found in resources", svc.Listener)
			continue
		}
		h.handle.SetProxyRedirect(name, proxyPort)
		if _, ok := h.redirected[name]; !ok {
			h.handle.Observe(name)
		}
		h.redirected[name] = svc
		h.configServices[key].Add(name)
		removedServices.Delete(name)
	}
	for name := range removedServices {
		h.handle.RemoveProxyRedirect(name)
		h.handle.Unobserve(name)
	}

}
