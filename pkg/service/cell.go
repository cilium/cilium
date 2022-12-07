package service

import (
	"sync"
	"time"

	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/service/config"
)

type ServiceHandle interface {
	Close()
	Synchronized()

	// from redirectpolicymanager:
	DeleteService(frontend loadbalancer.L3n4Addr) (bool, error)
	UpsertService(*loadbalancer.SVC) (bool, loadbalancer.ID, error)

	// from k8s watcher. used in cilium_envoy_config.go and pod.go.
	RegisterL7LBService(serviceName, resourceName loadbalancer.ServiceName, ports []string, proxyPort uint16) error
	RegisterL7LBServiceBackendSync(serviceName, resourceName loadbalancer.ServiceName, ports []string) error
	RemoveL7LBService(serviceName, resourceName loadbalancer.ServiceName) error

	// from daemon/cmd/loadbalancer.go
	UpdateBackendsState([]*loadbalancer.Backend) error
	DeleteServiceByID(loadbalancer.ServiceID) (bool, error)
	GetDeepCopyServiceByID(loadbalancer.ServiceID) (*loadbalancer.SVC, bool)
	GetDeepCopyServices() []*loadbalancer.SVC

	// from daemon/cmd/state.go
	//SyncWithK8sFinished() error
}

type ServiceManager interface {
	// WaitUntilSynchronized blocks until all handles have
	// synchronized.
	WaitUntilSynchronized()

	NewHandle(name string) ServiceHandle

	SetMonitorNotify(monitorNotify)
	SetEnvoyCache(envoyCache)

	// from daemon/cmd/kube_proxy_healthz.go.
	GetLastUpdatedTs() time.Time
	GetCurrentTs() time.Time

	// from daemon/cmd/datapath.go
	InitMaps(ipv6, ipv4 bool, sockRevNat bool, restoreState bool) error

	// from daemon/cmd/hubble.go
	GetServiceNameByAddr(loadbalancer.L3n4Addr) (ns, name string, ok bool)

	// from daemon.go
	RestoreServices() error
	SyncServicesOnDeviceChange(datapathTypes.NodeAddressing)

	GetDeepCopyServiceByID(loadbalancer.ServiceID) (*loadbalancer.SVC, bool)
	GetDeepCopyServices() []*loadbalancer.SVC
}

const (
	moduleId = "service-manager"
)

var Cell = cell.Module(
	moduleId,
	"Manages the service and backend maps",

	cell.Provide(newServiceManager),
)

type serviceManagerParams struct {
	cell.In

	Lifecycle hive.Lifecycle
	Config    config.ServiceConfig
	LBMap     datapathTypes.LBMap
}

func newServiceManager(p serviceManagerParams) ServiceManager {
	svc := newService(
		p.Config,
		nil,
		nil,
		p.LBMap,
	)
	sm := &serviceManager{
		serviceManagerParams: p,
		Service:              svc,
	}

	// Add a sentinel that's marked done once we've started up
	// in order to allow handles to register and not incorrectly
	// signal readiness.
	sm.handleWG.Add(1)

	p.Lifecycle.Append(sm)
	return sm
}

// TODO: this currently just wraps '*Service' and throws on top the k8s event
// handling. Reimplement the event handling as "K8sServicesHandler" or some such
// and put the rest back into '*Service' (and rename it).
type serviceManager struct {
	serviceManagerParams
	*Service

	handleWG sync.WaitGroup
}

var _ ServiceManager = &serviceManager{}
var _ hive.HookInterface = &serviceManager{}

// Start implements hive.HookInterface
func (sm *serviceManager) Start(hive.HookContext) error {
	sm.handleWG.Done()

	go func() {
		// Wait for all handles to synchronize.
		sm.handleWG.Wait()

		// Garbage collect orphaned entries.
		err := sm.SyncWithK8sFinished()
		if err != nil {
			log.WithError(err).Error("Service GC failed")
		}
	}()

	return nil
}

// Stop implements hive.HookInterface
func (sm *serviceManager) Stop(hive.HookContext) error {
	return nil
}

// TODO: Check whether delayed assignment of these screws things up.
// Alternatively could depend optionally on Promise[Monitor], Promise[L7Proxy]
// and then assign when they're resolved and the follow-up actions if needed.
func (sm *serviceManager) SetMonitorNotify(m monitorNotify) {
	sm.Lock()
	sm.monitorNotify = m
	sm.Unlock()
}

func (sm *serviceManager) SetEnvoyCache(e envoyCache) {
	sm.Lock()
	sm.envoyCache = e
	sm.Unlock()
}

func (sm *serviceManager) NewHandle(name string) ServiceHandle {
	sm.handleWG.Add(1)
	return &serviceHandle{sm.Service, sm}
}

func (sm *serviceManager) WaitUntilSynchronized() {
	sm.handleWG.Wait()
}

type serviceHandle struct {
	*Service
	sm *serviceManager
}

var _ ServiceHandle = &serviceHandle{}

func (h *serviceHandle) Close() {
}

func (h *serviceHandle) Synchronized() {
	h.sm.handleWG.Done()
}
