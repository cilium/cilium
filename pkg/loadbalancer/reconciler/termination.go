// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package reconciler

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"net"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/datapath/sockets"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
)

// SocketTerminationCell runs a background job that monitors the backends table for
// unhealthy and deleted backends and terminates UDP & TCP sockets connected to these
// backends to signal to the application that the destination has become unreachable.
var SocketTerminationCell = cell.Module(
	"socket-termination",
	"Terminates sockets connected to deleted backends",

	// Provide the default implementations for accessing network namespaces and
	// destroying sockets. This allows the tests to use "registerSocketTermination"
	// directly and provide custom implementations of these.
	cell.ProvidePrivate(
		func() netnsOps {
			return netnsOps{
				current: netns.Current,
				do:      (*netns.NetNS).Do,
				all:     netns.All,
			}
		},
		func() socketDestroyerFactory {
			return makeSocketDestroyer
		},
	),

	cell.Invoke(registerSocketTermination),
)

type socketTerminationParams struct {
	cell.In

	JobGroup  job.Group
	DB        *statedb.DB
	Backends  statedb.Table[*lb.Backend]
	Log       *slog.Logger
	Config    lb.Config
	ExtConfig lb.ExternalConfig
	LBMaps    maps.LBMaps
	Health    cell.Health

	MakeSocketDestroyer socketDestroyerFactory
	NetNSOps            netnsOps

	// TestSyncChan is used by the tests to synchronize with the job so it
	// knows when to delete the backend.
	TestSyncChan testSyncChan   `optional:"true"`
	TestConfig   *lb.TestConfig `optional:"true"`
}

type testSyncChan chan struct{}

// netnsOps captures the operations performed with network namespaces.
// This allows the tests to inject their own implementation.
type netnsOps struct {
	current func() (*netns.NetNS, error)
	do      func(*netns.NetNS, func() error) error
	all     func() (iter.Seq2[string, *netns.NetNS], <-chan error)
}

// socketDestroyerFactory creates a level of indirection that makes it possible
// to inject mock SocketDestroyers in tests. SocketDestoyer cannot simply be
// Provide()ed above, since the invocation of NewSocketDestroyer must be
// deferred until all maps are created. We want to run it right before
// socketTerminationLoop is invoked.
type socketDestroyerFactory func(socketTerminationParams) (sockets.SocketDestroyer, error)

func makeSocketDestroyer(p socketTerminationParams) (sockets.SocketDestroyer, error) {
	sockRevNat4, sockRevNat6 := p.LBMaps.SockRevNat()
	sd, err := sockets.NewSocketDestroyer(p.Log, sockRevNat4, sockRevNat6)
	if err != nil {
		return nil, err
	}

	return sd, nil
}

func registerSocketTermination(p socketTerminationParams) error {
	if !(p.ExtConfig.EnableSocketLB || p.ExtConfig.BPFSocketLBHostnsOnly) {
		return nil
	}

	if err := sockets.InetDiagDestroyEnabled(p.Log, p.Config.LBSockTerminateAllProtos, true); err != nil {
		if errors.Is(err, probes.ErrNotSupported) {
			// The kernel doesn't support socket termination.
			p.Log.Error("Forcefully terminating sockets connected to deleted service backends "+
				"not supported by underlying kernel", logfields.Error, err)
			p.Health.Degraded("service LV socket termination not supported by kernel", err)
			return nil
		}
		p.Log.Error("Unexpected error while probing kernel socket termination support."+
			"Will proceed with starting socket destroyer job but functionality may be degraded",
			logfields.Error, err)
		p.Health.Degraded("Unexpected error while probing kernel socket termination support",
			err)
	}
	p.JobGroup.Add(
		job.OneShot(
			"socket-termination",
			func(ctx context.Context, h cell.Health) error {
				sd, err := p.MakeSocketDestroyer(p)
				if err != nil {
					return fmt.Errorf("creating socket destroyer: %w", err)
				}

				return socketTerminationLoop(p, sd, ctx, h)
			},
		))

	return nil
}

func socketTerminationLoop(p socketTerminationParams, sd sockets.SocketDestroyer, ctx context.Context, health cell.Health) error {
	wtxn := p.DB.WriteTxn(p.Backends)
	changeIter, err := p.Backends.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return err
	}

	// Process the changes in batches every 50 milliseconds.
	limiter := rate.NewLimiter(50*time.Millisecond, 1)
	defer limiter.Stop()

	for {
		changes, watch := changeIter.Next(p.DB.ReadTxn())
		for change := range changes {
			backend := change.Object

			if p.TestSyncChan != nil {
				close(p.TestSyncChan)
				p.TestSyncChan = nil
			}

			if backend.Address.Protocol() != lb.UDP &&
				backend.Address.Protocol() != lb.TCP {
				continue
			}

			// Terminate the sockets connected to backends that have been either
			// deleted or which are no longer considered viable.
			if change.Deleted || !backend.IsAlive() {
				opSupported := terminateConnectionsToBackend(p, sd, backend.Address)
				if !opSupported {
					// The kernel doesn't support socket termination. We can stop processing.
					p.Log.Error("Forcefully terminating sockets connected to deleted service backends " +
						"not supported by underlying kernel: see kube-proxy free guide for " +
						"the required kernel configurations")
					return nil
				}
			}
		}

		select {
		case <-watch:
		case <-ctx.Done():
			return ctx.Err()
		}
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
	}
}

// terminateConnectionsToBackend closes UDP & TCP connection sockets that match
// the destination l3/l4 tuple addr that also are tracked in the sock rev nat map
// (including socket cookie).
func terminateConnectionsToBackend(p socketTerminationParams, sd sockets.SocketDestroyer, l3n4Addr lb.L3n4Addr) (opSupported bool) {
	opSupported = true

	var (
		family   uint8
		protocol uint8
		states   uint32
	)
	ip := net.IP(l3n4Addr.Addr().AsSlice())

	switch l3n4Addr.Protocol() {
	case lb.UDP:
		protocol = unix.IPPROTO_UDP
		states = sockets.StateFilterUDP
	case lb.TCP:
		protocol = unix.IPPROTO_TCP
		states = sockets.StateFilterTCP
		// Currently terminating TCP is false by default since iterating
		// TCP sockets can become expensive compared to UDP due to the
		// sheer number of sockets in the system. Once this is optimized
		// where the cost is significantly reduced, the hidden config flag
		// can be removed.
		if !p.Config.LBSockTerminateAllProtos {
			return
		}
	default:
		return
	}

	p.Log.Debug("Terminating sockets connected to deleted backend", logfields.Deleted, l3n4Addr)

	if l3n4Addr.IsIPv6() {
		family = syscall.AF_INET6
	} else {
		family = syscall.AF_INET
	}

	// Filter pod connections load-balanced to the passed service backend.
	//
	// When pod traffic is load-balanced to service backends, the cilium datapath
	// records entries in the sock rev nat map that store the pod socket cookie
	// (unique identifier in the kernel) along with the destination backend ip/port.
	checkSockInRevNat := func(id netlink.SocketID) bool {
		cookie := uint64(id.Cookie[1])
		cookie = cookie<<32 + uint64(id.Cookie[0])
		return p.LBMaps.ExistsSockRevNat(cookie, id.Destination, id.DestinationPort)
	}

	destroy := func(nsName string, ns *netns.NetNS) error {
		err := p.NetNSOps.do(ns, func() error {
			return sd.Destroy(p.Log, sockets.SocketFilter{
				Family:    family,
				Protocol:  protocol,
				States:    states,
				DestIp:    ip,
				DestPort:  l3n4Addr.Port(),
				DestroyCB: checkSockInRevNat,
			})
		})

		if err != nil {
			if errors.Is(err, unix.EOPNOTSUPP) {
				opSupported = false
				return err
			} else {
				p.Log.Error(
					"error while forcefully terminating sockets connected to "+
						"deleted service backend. Consider restarting any application pods sending traffic "+
						"to the backend",
					logfields.Error, err,
					logfields.L3n4Addr, l3n4Addr,
					logfields.NetNSName, nsName,
				)
			}
		}
		return nil
	}

	// Terminate sockets in host namespace
	if hostNS, err := p.NetNSOps.current(); err == nil {
		destroy("<host>", hostNS)
	}

	// Iterate over all pod network namespaces, and terminate any stale connections.
	if p.ExtConfig.EnableSocketLBPodConnectionTermination && !p.ExtConfig.BPFSocketLBHostnsOnly {
		iter, errs := p.NetNSOps.all()
		if iter != nil {
			for name, ns := range iter {
				destroy(name, ns)
			}
		}
		for err := range errs {
			p.Log.Debug("Error opening netns, skipping",
				logfields.Error, err)
		}
	}

	return
}
