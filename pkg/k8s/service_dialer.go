package k8s

import (
	"context"
	"fmt"
	"net"
	"net/url"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/sirupsen/logrus"
	"go.uber.org/multierr"
)

type ServiceDialer interface {
	Dial(ctx context.Context, addr string) (net.Conn, error)
}

type serviceDialerParams struct {
	cell.In
	Endpoints resource.Resource[*Endpoints]
}

type serviceDialer struct {
	serviceDialerParams
}

func newServiceDialer(p serviceDialerParams) ServiceDialer {
	return &serviceDialer{p}
}

func (s *serviceDialer) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return dialService(s, ctx, addr)
}

func dialService(s *serviceDialer, ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer

	// If the service is available, do the service translation to
	// the service IP. Otherwise dial with the original service
	// name `s`.
	u, err := url.Parse(addr)
	if err == nil {
		var svc *ServiceID
		// In etcd v3.5.0, 's' doesn't contain the URL Scheme and the u.Host
		// will be empty because url.Parse will consider the "host" as the
		// url Scheme. If 's' doesn't contain the URL Scheme then we will be
		// able to parse the service ID directly from it without the need
		// to do url.Parse.
		if u.Host != "" {
			svc = ParseServiceIDFrom(u.Host)
		} else {
			svc = ParseServiceIDFrom(addr)
		}
		if svc != nil {
			trackCtx, trackCancel := context.WithCancel(ctx)
			defer trackCancel()

			endpointsTracker := s.Endpoints.Tracker(trackCtx)

			//endpointsTracker.TrackLabels()
			panic("TBD TrackLabels")

			var errs error

			// Try out each of the backends until we succeed or the context expires.
			for event := range endpointsTracker.Events() {
				event.Done(nil)
				if event.Kind != resource.Upsert {
					continue
				}
				for beAddr, be := range event.Object.Backends {
					for _, port := range be.Ports {
						conn, err := d.DialContext(ctx, port.Protocol, fmt.Sprintf("%s:%d", beAddr, port.Port))
						if err == nil {
							return conn, err
						} else {
							errs = multierr.Append(errs, err)
						}
					}
				}
			}
			errs = multierr.Append(errs, ctx.Err())
			return nil, errs
		} else {
			log.WithFields(logrus.Fields{"url-host": u.Host, "url": s}).Debug("Unable to parse etcd service URL into a service ID")
		}
		log.Debugf("custom dialer based on k8s service backend is dialing to %q", s)
	} else {
		log.WithError(err).Error("Unable to parse etcd service URL")
	}

	return d.DialContext(ctx, "tcp", addr)

}
