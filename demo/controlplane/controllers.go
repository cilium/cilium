package controlplane

import (
	"context"

	"github.com/cilium/cilium/demo/datapath"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/sirupsen/logrus"
)

var servicesControllerCell = cell.Module(
	"services-controller",
	"Computes service load-balancing desired state",

	// Register a controller to compute the desired frontends and backends
	// from K8s's Services and Endpoints.
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
	// Start tracking deletions of services and endpoints. This informs statedb
	// to keep a deleted object around until we can observe it.
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
		// oN when the control loop has last run and how long it took.
		health.OK("OK")

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
		s.Log.Infof("Deleted all backends for %s", ep.Service)
		return
	}

	newIDs := datapath.NewImmSet[datapath.ID]()
	for _, addr := range ep.Addrs {
		for _, portAndProto := range ep.Ports {
			beKey := datapath.BackendKey{
				Addr:     addr,
				Protocol: datapath.L4Proto(portAndProto.Protocol),
				Port:     portAndProto.Port,
			}
			id := s.Backends.Upsert(
				s.wtxn,
				ep.Service,
				beKey,
			)
			newIDs = newIDs.Insert(id)
			s.Log.Infof("Inserted backend %v", beKey)
		}
	}

	// Update the frontend to refer to the new backends.
	s.Frontends.UpdateBackends(s.wtxn, ep.Service, newIDs)
}

func (s *servicesController) serviceChanged(svc *Service, deleted bool, rev statedb.Revision) {
	if deleted {
		s.Log.Infof("Deleted frontend %q", svc.Name)
		s.Frontends.Delete(s.wtxn, svc.Name)
	} else {

		meta := datapath.FrontendMeta{
			Name:     svc.Name,
			Addr:     svc.ClusterIP,
			Protocol: datapath.L4Proto(svc.Protocol),
			Port:     svc.Port,
			Type:     string(svc.ServiceType),
		}

		s.Log.Infof("Inserted frontend %q", meta.Name)
		s.Frontends.Upsert(s.wtxn, meta)
	}
}
