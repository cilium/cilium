// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path"
	"sync"

	"github.com/cilium/hive/cell"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"istio.io/istio/pkg/zdsapi"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/iptables"
)

type ztunnelConn struct {
	conn *net.UnixConn
}

func (zc *ztunnelConn) Close() error {
	return zc.conn.Close()
}

func (zc *ztunnelConn) readHello() (*zdsapi.ZdsHello, error) {
	hello := &zdsapi.ZdsHello{}
	if err := zc.readMsg(hello); err != nil {
		return nil, err
	}
	return hello, nil
}

func (zc *ztunnelConn) readResponse() (*zdsapi.WorkloadResponse, error) {
	resp := &zdsapi.WorkloadResponse{}
	if err := zc.readMsg(resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func (zc *ztunnelConn) readMsg(msg proto.Message) error {
	var buf [1024]byte
	n, err := zc.conn.Read(buf[:])
	if err != nil {
		return err
	}

	return proto.Unmarshal(buf[:n], msg)
}

func (zc *ztunnelConn) sendMsg(req *zdsapi.WorkloadRequest, ns *netns.NetNS) error {
	var rights []byte
	if ns != nil {
		rights = unix.UnixRights(ns.FD())
		defer ns.Close()
	}
	data, err := proto.Marshal(req)
	if err != nil {
		return err
	}

	_, _, err = zc.conn.WriteMsgUnix(data, rights, nil)
	return err
}

func (zc *ztunnelConn) sendAndWaitForAck(req *zdsapi.WorkloadRequest, ns *netns.NetNS) error {
	if err := zc.sendMsg(req, ns); err != nil {
		return err
	}

	resp, err := zc.readResponse()
	if err != nil {
		return err
	}

	if resp.GetAck() != nil && resp.GetAck().GetError() != "" {
		return fmt.Errorf("ztunnel responded with an ack error: %s", resp.GetAck().GetError())
	}

	return nil
}

func endpointToWorkload(ep *endpoint.Endpoint) *zdsapi.AddWorkload {
	namespace := ep.GetK8sNamespace()
	name := ep.GetK8sPodName()
	svcAccount := ep.GetPod().Spec.ServiceAccountName
	return &zdsapi.AddWorkload{
		WorkloadInfo: &zdsapi.WorkloadInfo{
			Namespace:      namespace,
			Name:           name,
			ServiceAccount: svcAccount,
		},
		Uid: string(ep.GetPod().GetUID()),
	}
}

const (
	maxZtunnelConnections = 2
)

type serverParams struct {
	cell.In

	Lifecycle cell.Lifecycle
	Logger    *slog.Logger
	Config    config.Config

	EndpointManager endpointmanager.EndpointManager
}

type serverOut struct {
	cell.Out
	*Server
	EndpointEnroller
}

// EndpointEnroller allows enrolling and disenrolling endpoints to/from the ztunnel.
type EndpointEnroller interface {
	InitialSnapshot(ep ...*endpoint.Endpoint) error
	EnrollEndpoint(ep *endpoint.Endpoint) error
	DisenrollEndpoint(ep *endpoint.Endpoint) error
}

var _ EndpointEnroller = &Server{}

type Server struct {
	l      *net.UnixListener
	logger *slog.Logger

	endpointCache      map[uint16]*endpoint.Endpoint
	endpointCacheMutex lock.Mutex

	zc            *ztunnelConn // active connection
	zcInitialized chan struct{}
	activeMu      lock.Mutex // serialized access to active zc

	updates             chan zdsUpdate // updates to send to ztunnel
	initialSnapshotSent chan struct{}
}

type zdsUpdate struct {
	request *zdsapi.WorkloadRequest
	ns      *netns.NetNS
}

func newZDSServer(p serverParams) serverOut {
	server := &Server{
		logger:              p.Logger,
		updates:             make(chan zdsUpdate, 100),
		endpointCache:       make(map[uint16]*endpoint.Endpoint),
		initialSnapshotSent: make(chan struct{}),
		zcInitialized:       make(chan struct{}),
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			err := os.RemoveAll(p.Config.ZDSUnixAddr)
			if err != nil {
				return err
			}

			// if we need to create the basedir for the ZDSUnixAddr, do it
			if err := os.MkdirAll(path.Dir(p.Config.ZDSUnixAddr), 0755); err != nil {
				return fmt.Errorf("failed to create ztunnel unix addr directory: %w", err)
			}

			resolvedAddr, err := net.ResolveUnixAddr("unixpacket", p.Config.ZDSUnixAddr)
			if err != nil {
				return fmt.Errorf("failed to resolve ztunnel unix addr: %w", err)
			}

			server.l, err = net.ListenUnix("unixpacket", resolvedAddr)
			if err != nil {
				return fmt.Errorf("failed to listen on ztunnel unix addr: %w", err)
			}

			wg.Add(1)
			go func() {
				defer wg.Done()
				server.Serve(ctx)
			}()

			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()
			wg.Wait()
			return nil
		},
	})

	out := serverOut{
		Server:           server,
		EndpointEnroller: server,
	}

	return out
}

func (s *Server) Serve(ctx context.Context) {
	// Start a goroutine to close the listener when the context is canceled.
	// This will cause Accept() to return an error, unblocking the main loop.
	go func() {
		<-ctx.Done()
		s.l.Close()
	}()

	sem := semaphore.NewWeighted(int64(maxZtunnelConnections))

	for {
		conn, err := s.l.AcceptUnix()
		if err != nil {
			// If the context is done, this is an expected error on shutdown.
			if ctx.Err() != nil {
				return
			}
			s.logger.Error("failed to accept connection", logfields.Error, err)
			return
		}
		s.zc = &ztunnelConn{conn: conn}
		close(s.zcInitialized)

		if !sem.TryAcquire(1) {
			conn.Close()
			continue
		}

		go func() {
			if err := s.handleConn(ctx); err != nil {
				s.logger.Error("failed to handle connection", logfields.Error, err)
			}
			sem.Release(1)
		}()
	}
}

func (s *Server) handleConn(ctx context.Context) error {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	defer s.zc.Close()
	s.logger.Info("new ztunnel connection")

	hello, err := s.zc.readHello()
	if err != nil {
		return fmt.Errorf("failed to read hello from ztunnel: %w", err)
	}
	s.logger.Info("received hello from ztunnel", logfields.Version, hello.GetVersion())

	s.logger.Info("waiting for initial snapshot to be sent")
	<-s.initialSnapshotSent
	s.logger.Info("initial snapshot sent, processing updates")

	for {
		select {
		case update := <-s.updates:
			if err := s.zc.sendAndWaitForAck(update.request, update.ns); err != nil {
				return fmt.Errorf("failed to send update: %w", err)
			}

		case <-ctx.Done():
			s.logger.Info("context cancelled, closing ztunnel connection")
			return nil
		}
	}
}

func (s *Server) EnrollEndpoint(ep *endpoint.Endpoint) error {
	s.logger.Info("enrolling endpoint to ztunnel", logfields.EndpointID, ep.GetID16())
	s.endpointCacheMutex.Lock()
	defer s.endpointCacheMutex.Unlock()
	// if the endpoint is already in the cache, ztunnel already received it
	if _, ok := s.endpointCache[ep.GetID16()]; ok {
		s.logger.Info("endpoint already in ztunnel", logfields.EndpointID, ep.GetID16())
		return nil
	}
	s.logger.Info("adding endpoint to ztunnel", logfields.EndpointID, ep.GetID16())
	s.endpointCache[ep.GetID16()] = ep

	req := &zdsapi.WorkloadRequest{
		Payload: &zdsapi.WorkloadRequest_Add{
			Add: endpointToWorkload(ep),
		},
	}

	ns, err := netns.OpenPinned(ep.GetContainerNetnsPath())
	if err != nil {
		s.logger.Error("failed to open netns file",
			logfields.EndpointID, ep.GetID16(),
			logfields.Error, err,
		)
		return err
	}

	if err = ns.Do(func() error {
		return iptables.CreateInPodRules(s.logger, option.Config.EnableIPv4, option.Config.EnableIPv6)
	}); err != nil {
		return fmt.Errorf("unable to setup iptable rules for ztunnel inpod mode: %w", err)
	}

	s.updates <- zdsUpdate{
		request: req,
		ns:      ns,
	}
	return nil
}

func (s *Server) DisenrollEndpoint(ep *endpoint.Endpoint) error {
	s.logger.Info("disenrolling endpoint from ztunnel", logfields.EndpointID, ep.GetID16())
	s.endpointCacheMutex.Lock()
	defer s.endpointCacheMutex.Unlock()
	delete(s.endpointCache, ep.GetID16())
	req := &zdsapi.WorkloadRequest{
		Payload: &zdsapi.WorkloadRequest_Del{
			Del: &zdsapi.DelWorkload{
				Uid: string(ep.GetPod().GetUID()),
			},
		},
	}

	ns, err := netns.OpenPinned(ep.GetContainerNetnsPath())
	if err != nil {
		s.logger.Error("failed to open netns file",
			logfields.EndpointID, ep.GetID16(),
			logfields.Error, err,
		)
		return err
	}

	if err = ns.Do(func() error {
		return iptables.DeleteInPodRules(s.logger, option.Config.EnableIPv4, option.Config.EnableIPv6)
	}); err != nil {
		return fmt.Errorf("unable to remove iptable rules for ztunnel inpod mode: %w", err)
	}

	s.updates <- zdsUpdate{
		request: req,
		ns:      nil,
	}
	return nil
}

func (s *Server) InitialSnapshot(eps ...*endpoint.Endpoint) error {
	s.logger.Info("waiting for ztunnel connection to be established")
	<-s.zcInitialized
	s.logger.Info("ztunnel connection established, sending initial snapshot")
	s.endpointCacheMutex.Lock()
	defer s.endpointCacheMutex.Unlock()
	for _, ep := range eps {
		if _, ok := s.endpointCache[ep.GetID16()]; ok {
			continue
		}
		s.endpointCache[ep.GetID16()] = ep
		req := &zdsapi.WorkloadRequest{
			Payload: &zdsapi.WorkloadRequest_Add{
				Add: endpointToWorkload(ep),
			},
		}

		ns, err := netns.OpenPinned(ep.GetContainerNetnsPath())
		if err != nil {
			s.logger.Error("failed to open netns file",
				logfields.EndpointID, ep.GetID16(),
				logfields.Error, err,
			)
			return err
		}

		if err = ns.Do(func() error {
			return iptables.CreateInPodRules(s.logger, option.Config.EnableIPv4, option.Config.EnableIPv6)
		}); err != nil {
			return fmt.Errorf("unable to setup iptable rules for ztunnel inpod mode: %w", err)
		}

		if err := s.zc.sendAndWaitForAck(req, ns); err != nil {
			return fmt.Errorf("failed to send endpoint message: %w", err)
		}
	}
	req := &zdsapi.WorkloadRequest{
		Payload: &zdsapi.WorkloadRequest_SnapshotSent{
			SnapshotSent: &zdsapi.SnapshotSent{},
		},
	}

	if err := s.zc.sendAndWaitForAck(req, nil); err != nil {
		return fmt.Errorf("failed to send snapshot message: %w", err)
	}
	s.logger.Info("snapshot sent to ztunnel")
	close(s.initialSnapshotSent)
	return nil
}
