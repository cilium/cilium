package controlplane

import (
	"context"
	"time"

	"github.com/cilium/cilium/demo/datapath"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/sirupsen/logrus"
)

var controllersCell = cell.Module(
	"controlplane-controllers",
	"Demo controllers",

	cell.Invoke(registerServicesController),
)

type servicesControllerParams struct {
	cell.In

	Scope     cell.Scope
	Lifecycle hive.Lifecycle
	Jobs      job.Registry
	Log       logrus.FieldLogger

	DB        *statedb.DB
	Services  statedb.Table[*Service]
	Endpoints statedb.Table[*Endpoint]

	Frontends datapath.Frontends
	Backends  datapath.Backends
}

func registerServicesController(p servicesControllerParams) {
	ctrl := &servicesController{servicesControllerParams: p}
	g := p.Jobs.NewGroup(p.Scope)
	g.Add(job.OneShot("servicesController.process", ctrl.process))
	p.Lifecycle.Append(g)
}

// servicesController computes the new frontends and backends from K8s services and endpoints.
type servicesController struct {
	servicesControllerParams

	wtxn statedb.WriteTxn // Current write transaction
}

func (s *servicesController) process(ctx context.Context, health cell.HealthReporter) error {
	// Start tracking deletions of services and endpoints
	wtxn := s.DB.WriteTxn(s.Services, s.Endpoints)
	defer wtxn.Abort()
	endpointsTracker, err := s.Endpoints.DeleteTracker(wtxn, "servicesController")
	if err != nil {
		return err
	}
	defer endpointsTracker.Close()
	servicesTracker, err := s.Services.DeleteTracker(wtxn, "servicesController")
	if err != nil {
		return err
	}
	defer servicesTracker.Close()
	wtxn.Commit()

	var (
		endpointsWatch <-chan struct{}
		servicesWatch  <-chan struct{}
		limiter        = rate.NewLimiter(50*time.Millisecond, 3)
	)

	for {
		s.wtxn = s.DB.WriteTxn(s.Frontends, s.Backends)
		servicesWatch = servicesTracker.Iterate(
			s.wtxn,
			s.serviceChanged,
		)
		endpointsWatch = endpointsTracker.Iterate(
			s.wtxn,
			s.endpointChanged,
		)
		s.wtxn.Commit()
		s.wtxn = nil

		// TODO: for this sort of pattern we could have a e.g. job.Watcher which takes
		// a set of channels (see go-memdb's WatchSet). This would allow for more stats
		// on when the control loop has last run and how long it took.
		health.OK("OK")

		// Apply rate-limiting in order to process bigger batches of changes at a time
		// for increased throughput.
		limiter.Wait(ctx)

		select {
		case <-ctx.Done():
			return nil
		case <-endpointsWatch:
		case <-servicesWatch:
		}
	}
}

func (s *servicesController) endpointChanged(ep *Endpoint, deleted bool, rev statedb.Revision) {
	if deleted {
		s.deleteEndpoint(ep)
	} else {
		s.upsertEndpoint(ep)
	}
}

func (s *servicesController) deleteEndpoint(ep *Endpoint) {
	fe, _, ok := s.Frontends.First(s.wtxn, datapath.FrontendNameIndex.Query(ep.Service))
	if ok {
		s.Frontends.Upsert(s.wtxn, fe.WithBackends(nil))
	}
}

func (s *servicesController) upsertEndpoint(ep *Endpoint) {
	// Allocate the new backends
	newIDs := datapath.ImmSet[datapath.BackendID]{}
	for _, addr := range ep.Addrs {
		for _, portAndProto := range ep.Ports {
			beKey := datapath.BackendKey{
				Addr:     addr,
				Protocol: datapath.L4Proto(portAndProto.Protocol),
				Port:     portAndProto.Port,
			}
			s.Log.Infof("Inserted backend %v", beKey)
			id := s.Backends.Upsert(
				s.wtxn,
				ep.Service,
				beKey,
			)
			newIDs = newIDs.Insert(id)
		}
	}

	// Look up the frontend whose backends we're updating. It may
	// have not yet been created in which case the backend update
	// will be done when the frontend is created.
	fe, _, ok := s.Frontends.First(s.wtxn, datapath.FrontendNameIndex.Query(ep.Service))
	if ok {
		s.Frontends.Upsert(s.wtxn, fe.WithBackends(newIDs))
	}
}

func (s *servicesController) serviceChanged(svc *Service, deleted bool, rev statedb.Revision) {
	if deleted {
		s.Frontends.Delete(s.wtxn, svc.Name)
	} else {
		s.upsertService(svc)
	}
}

func (s *servicesController) upsertService(svc *Service) {
	fe, _, ok := s.Frontends.First(s.wtxn, datapath.FrontendNameIndex.Query(svc.Name))
	if ok {
		fe = fe.Clone()
	} else {
		fe = &datapath.Frontend{
			Name:     svc.Name,
			Backends: s.Backends.ReferencedBy(s.wtxn, svc.Name),
		}
	}
	fe.Addr = svc.ClusterIP
	fe.Type = string(svc.ServiceType)
	fe.Port = svc.Port
	fe.Protocol = datapath.L4Proto(svc.Protocol)

	s.Log.Infof("Inserted frontend %q", fe.Name)
	s.Frontends.Upsert(s.wtxn, fe)
}
