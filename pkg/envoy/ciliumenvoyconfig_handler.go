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

	"github.com/cilium/cilium/pkg/controlplane/servicemanager"
	"github.com/cilium/cilium/pkg/hive"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

type serviceKey = resource.Key

var Cell = cell.Module(
	"envoy-cec-handler",
	"Manages L7 proxy redirection based on CiliumEnvoyConfig CRDs",

	cell.Provide(
		newCECHandler,
	),
)

type cecHandlerParams struct {
	cell.In

	ServiceManager servicemanager.ServiceManager
	Log            logrus.FieldLogger
	CECs           resource.Resource[*cilium_v2.CiliumEnvoyConfig]
	EnvoyCache     EnvoyCache
}

// TODO replace with real thing:
type EnvoyCache interface {
	UpsertEnvoyEndpoints(loadbalancer.ServiceName, map[string][]*loadbalancer.Backend) error
}

type cecHandler struct {
	params cecHandlerParams

	log logrus.FieldLogger

	handle servicemanager.ServiceHandle
}

func newCECHandler(log logrus.FieldLogger, lc hive.Lifecycle, p cecHandlerParams) *cecHandler {
	if p.CECs == nil {
		log.Info("K8s not available, not registering handler for redirect policies")
		return nil
	}

	handler := &cecHandler{
		params: p,
		log:    p.Log,
		handle: p.ServiceManager.NewHandle("l7proxy"),
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
	serviceEvents := h.handle.Events(ctx, false, nil)

	redirected := map[loadbalancer.ServiceName]*cilium_v2.ServiceListener{}

	for {
		select {
		case <-ctx.Done():
			return

		case ev := <-serviceEvents:
			_, ok := redirected[ev.Name()]
			if !ok {
				continue
			}
			backends := map[string][]*loadbalancer.Backend{}
			ev.ForEachBackend(func(be loadbalancer.Backend) {
				backends[be.FEPortName] = append(backends[be.FEPortName], &be)
			})
			h.params.EnvoyCache.UpsertEnvoyEndpoints(ev.Name(), backends)

		case ev := <-cecs:
			switch ev.Kind {
			case resource.Sync:
				// TODO
			case resource.Upsert:
				spec := ev.Object.Spec
				for _, svc := range spec.Services {
					name := loadbalancer.ServiceName{
						Scope:     loadbalancer.ScopeSVC,
						Namespace: svc.Namespace,
						Name:      svc.Name,
					}
					// Find the listener the service is to be redirected to
					var proxyPort uint16
					for _, l := range ev.Object.Listeners {
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

					fe := loadbalancer.Frontend{
						Name:          name,
						Type:          loadbalancer.SVCTypeL7Proxy,
						L7LBProxyPort: proxyPort,
					}
					h.handle.UpsertFrontend(name, &fe)
					redirected[name] = svc
				}
			case resource.Delete:
				for _, svc := range ev.Object.Services {
					name := loadbalancer.ServiceName{
						Scope:     loadbalancer.ScopeSVC,
						Namespace: svc.Namespace,
						Name:      svc.Name,
					}
					h.handle.DeleteFrontend(name, loadbalancer.L3n4Addr{}, loadbalancer.SVCTypeL7Proxy)
				}
			}
			ev.Done(nil)
		}
	}
}
