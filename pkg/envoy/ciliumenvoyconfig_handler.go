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
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"go.uber.org/multierr"

	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/controlplane/servicemanager"
	"github.com/cilium/cilium/pkg/hive"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/status"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

type serviceKey = resource.Key

var EnvoyConfigHandlerCell = cell.Module(
	"envoy-config-handler",
	"Handles L7 proxy redirection based on CiliumEnvoyConfig CRDs",

	cell.Invoke(registerCECHandler),
)

type cecHandlerParams struct {
	cell.In

	Lifecycle      hive.Lifecycle
	ServiceManager servicemanager.ServiceManager
	Log            logrus.FieldLogger
	CECs           resource.Resource[*cilium_v2.CiliumEnvoyConfig]
	CCECs          resource.Resource[*cilium_v2.CiliumClusterwideEnvoyConfig]
	EnvoyCache     EnvoyCache
	Reporter       status.Reporter
}

// TODO replace with real thing:
type EnvoyCache interface {
	UpsertEnvoyEndpoints(loadbalancer.ServiceName, map[string][]*loadbalancer.Backend) error
	UpsertEnvoyResources(context.Context, Resources) error
	PortAllocator
}

type redirectedTo struct {
	config    resource.Key
	proxyPort uint16
	listener  string
}

type cecHandler struct {
	params cecHandlerParams

	log logrus.FieldLogger

	handle         servicemanager.ServiceHandle
	configServices map[resource.Key]container.Set[loadbalancer.ServiceName]
	redirected     map[loadbalancer.ServiceName]redirectedTo

	faultyConfigs map[resource.Key]error
}

func registerCECHandler(p cecHandlerParams) {
	if p.CECs == nil {
		return
	}

	handler := &cecHandler{
		params:         p,
		log:            p.Log,
		handle:         p.ServiceManager.NewHandle("l7proxy"),
		configServices: map[resource.Key]container.Set[loadbalancer.ServiceName]{},
		redirected:     map[loadbalancer.ServiceName]redirectedTo{},
		faultyConfigs:  map[resource.Key]error{},
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	p.Lifecycle.Append(
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
}

func (h *cecHandler) processLoop(ctx context.Context) {
	cecs := h.params.CECs.Events(ctx)
	ccecs := h.params.CCECs.Events(ctx)
	cecsSynced, ccecsSynced := false, false
	serviceEvents := h.handle.Events()

	h.params.Reporter.OK()

	for {
		select {
		case <-ctx.Done():
			h.params.Reporter.Down("Stopped")
			h.handle.Close()
			return

		case ev, ok := <-serviceEvents:
			if !ok {
				serviceEvents = nil
				continue
			}

			_, ok = h.redirected[ev.Name]
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

		case ev, ok := <-cecs:
			if !ok {
				cecs = nil
				continue
			}
			switch ev.Kind {
			case resource.Sync:
				cecsSynced = true
				if cecsSynced && ccecsSynced {
					h.handle.Synchronized()
				}
			case resource.Upsert:
				h.upsert(ev.Key, &ev.Object.Spec)
			case resource.Delete:
				h.delete(ev.Key)
			}
			ev.Done(nil)

		case ev, ok := <-ccecs:
			if !ok {
				ccecs = nil
				continue
			}
			switch ev.Kind {
			case resource.Sync:
				ccecsSynced = true
				if cecsSynced && ccecsSynced {
					h.handle.Synchronized()
				}
			case resource.Upsert:
				h.upsert(ev.Key, &ev.Object.Spec)
			case resource.Delete:
				h.delete(ev.Key)
			}
			ev.Done(nil)
		}
	}
}

func (h *cecHandler) delete(key resource.Key) {
	svcs := h.configServices[key]
	for name, _ := range svcs {
		h.handle.RemoveProxyRedirect(name)
		h.handle.Unobserve(name)
		delete(h.redirected, name)
	}
	delete(h.configServices, key)
	delete(h.faultyConfigs, key)
	h.updateStatus()
}

func (h *cecHandler) upsert(key resource.Key, spec *cilium_v2.CiliumEnvoyConfigSpec) {
	defer h.updateStatus()

	resources, err := ParseResources(
		key.Namespace,
		key.Name,
		spec.Resources,
		true,
		h.params.EnvoyCache,
	)
	if err != nil {
		h.faultyConfigs[key] = fmt.Errorf("CiliumEnvoyConfig parse error: %w", err)
		return
	}

	removedServices := h.configServices[key].Clone()
	h.configServices[key] = container.NewSet[loadbalancer.ServiceName]()
	delete(h.faultyConfigs, key)

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
			h.faultyConfigs[key] =
				multierr.Append(
					h.faultyConfigs[key],
					fmt.Errorf("Listener %q for service %s/%s not found from resources",
						svc.Listener, svc.Namespace, svc.Name),
				)
			continue
		}
		if old, ok := h.redirected[name]; !ok {
			h.handle.SetProxyRedirect(name, proxyPort)
			h.handle.Observe(name)
		} else if old.config != key {
			h.faultyConfigs[key] =
				multierr.Append(
					h.faultyConfigs[key],
					fmt.Errorf("Refusing service %s/%s referenced by %s as it overlaps with %s",
						svc.Namespace, svc.Name, key, old.config))
			continue
		} else if old.proxyPort != proxyPort {
			h.handle.SetProxyRedirect(name, proxyPort)
		}
		h.redirected[name] = redirectedTo{key, proxyPort, svc.Listener}
		h.configServices[key].Add(name)
		removedServices.Delete(name)
	}
	for name := range removedServices {
		h.handle.RemoveProxyRedirect(name)
		h.handle.Unobserve(name)
	}
}

func (h *cecHandler) updateStatus() {
	faults := []string{}
	for key, err := range h.faultyConfigs {
		faults = append(faults, fmt.Sprintf("%s: %s", key, err))
	}
	if len(faults) == 0 {
		h.params.Reporter.OK()
	} else {
		h.params.Reporter.Degraded(strings.Join(faults, "\n"))
	}
}
