// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package zds

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
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
	"github.com/cilium/cilium/pkg/ztunnel/config"
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
		Uid: ep.GetK8sUID(),
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

type Server struct {
	l      *net.UnixListener
	logger *slog.Logger

	endpointCache      map[uint16]*endpoint.Endpoint
	deferredEndpoints  []*endpoint.Endpoint
	subscribed         bool
	endpointCacheMutex lock.Mutex

	zc       *ztunnelConn // active connection
	activeMu sync.Mutex   // serialized access to active zc

	updates chan zdsUpdate // updates to send to ztunnel
}

type zdsUpdate struct {
	request *zdsapi.WorkloadRequest
	ns      *netns.NetNS
}

func newZDSServer(p serverParams) (*Server, error) {
	server := &Server{
		logger:  p.Logger,
		updates: make(chan zdsUpdate, 100),
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	p.Lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			err := os.RemoveAll(p.Config.ZDSUnixAddr)
			if err != nil {
				return err
			}

			resolvedAddr, err := net.ResolveUnixAddr("unixpacket", p.Config.ZDSUnixAddr)
			if err != nil {
				return fmt.Errorf("failed to resolve ztunnel unix addr: %w", err)
			}

			server.l, err = net.ListenUnix("unixpacket", resolvedAddr)
			if err != nil {
				return fmt.Errorf("failed to listen on ztunnel unix addr: %w", err)
			}

			server.subscribeToEndpointEvents(p.EndpointManager)

			wg.Add(1)
			go func() {
				defer wg.Done()
				server.Serve(ctx)
			}()

			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			cancel()

			p.EndpointManager.Unsubscribe(server)
			wg.Wait()
			return nil
		},
	})

	return server, nil
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
			s.logger.Error("failed to accept connection", "err", err)
			return
		}

		if !sem.TryAcquire(1) {
			conn.Close()
			continue
		}

		go func() {
			if err := s.handleConn(ctx, &ztunnelConn{conn: conn}); err != nil {
				s.logger.Error("failed to handle connection", logfields.Error, err)
			}
			sem.Release(1)
		}()
	}
}

func (s *Server) handleConn(ctx context.Context, zc *ztunnelConn) error {
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	defer zc.Close()
	s.logger.Info("new ztunnel connection")

	hello, err := zc.readHello()
	if err != nil {
		return fmt.Errorf("failed to read hello from ztunnel: %w", err)
	}
	s.logger.Info("received hello from ztunnel", "version", hello.GetVersion())

	if err := s.sendSnapshot(zc); err != nil {
		return fmt.Errorf("failed to send snapshot: %w", err)
	}

	// send deferred endpoints
	for _, ep := range s.deferredEndpoints {
		s.EndpointCreated(ep)
	}

	for {
		select {
		case update := <-s.updates:
			if err := zc.sendAndWaitForAck(update.request, update.ns); err != nil {
				return fmt.Errorf("failed to send update: %w", err)
			}

		case <-ctx.Done():
			s.logger.Info("context cancelled, closing ztunnel connection")
			return nil
		}
	}
}

func (s *Server) sendSnapshot(zc *ztunnelConn) error {
	s.endpointCacheMutex.Lock()
	defer s.endpointCacheMutex.Unlock()
	for id, ep := range s.endpointCache {
		s.logger.Info("sending endpoint as part of snapshot", "endpointID", id)

		req := &zdsapi.WorkloadRequest{
			Payload: &zdsapi.WorkloadRequest_Add{
				Add: endpointToWorkload(ep),
			},
		}

		ns, err := netns.OpenPinned(ep.GetContainerNetnsPath())
		if err != nil {
			return fmt.Errorf("failed to open netns file: %v", err)
		}

		// this will implicitly close the netns file
		if err := zc.sendAndWaitForAck(req, ns); err != nil {
			return fmt.Errorf("failed to send endpoint message: %w", err)
		}
	}

	req := &zdsapi.WorkloadRequest{
		Payload: &zdsapi.WorkloadRequest_SnapshotSent{
			SnapshotSent: &zdsapi.SnapshotSent{},
		},
	}

	if err := zc.sendAndWaitForAck(req, nil); err != nil {
		return fmt.Errorf("failed to send snapshot message: %w", err)
	}
	s.subscribed = true
	s.logger.Info("snapshot sent to ztunnel")

	return nil
}

func (s *Server) subscribeToEndpointEvents(epm endpointmanager.EndpointManager) {
	epm.Subscribe(s)
	localEPs := epm.GetEndpoints()

	s.endpointCacheMutex.Lock()
	defer s.endpointCacheMutex.Unlock()

	s.endpointCache = map[uint16]*endpoint.Endpoint{}
	for _, ep := range localEPs {
		if !ep.NeedsZtunnel() {
			s.logger.Info("endpoint does not need ztunnel", "endpointID", ep.GetID16())
			continue
		}
		s.endpointCache[ep.GetID16()] = ep
	}
}

func (s *Server) EndpointCreated(ep *endpoint.Endpoint) {
	if !ep.NeedsZtunnel() {
		s.logger.Info("endpoint does not need ztunnel", "endpointID", ep.GetID16())
		return
	}

	s.endpointCacheMutex.Lock()
	defer s.endpointCacheMutex.Unlock()
	// if the endpoint is already in the cache, ztunnel already received it
	if _, ok := s.endpointCache[ep.GetID16()]; ok {
		s.logger.Info("endpoint already in ztunnel", "endpointID", ep.GetID16())
		return
	}

	if !s.subscribed {
		s.deferredEndpoints = append(s.deferredEndpoints, ep)
		return
	}

	s.logger.Info("adding endpoint to ztunnel", "endpointID", ep.GetID16())
	s.endpointCache[ep.GetID16()] = ep

	req := &zdsapi.WorkloadRequest{
		Payload: &zdsapi.WorkloadRequest_Add{
			Add: endpointToWorkload(ep),
		},
	}

	ns, err := netns.OpenPinned(ep.GetContainerNetnsPath())
	if err != nil {
		s.logger.Error("failed to open netns file", "endpointID", ep.GetID16(), "err", err)
		return
	}

	s.updates <- zdsUpdate{
		request: req,
		ns:      ns,
	}
}

func (s *Server) EndpointDeleted(ep *endpoint.Endpoint, conf endpoint.DeleteConfig) {
	s.logger.Info("removing endpoint from ztunnel", "endpointID", ep.GetID16())
	s.endpointCacheMutex.Lock()
	defer s.endpointCacheMutex.Unlock()
	delete(s.endpointCache, ep.GetID16())

	req := &zdsapi.WorkloadRequest{
		Payload: &zdsapi.WorkloadRequest_Del{
			Del: &zdsapi.DelWorkload{
				Uid: ep.GetK8sUID(),
			},
		},
	}

	s.updates <- zdsUpdate{
		request: req,
		ns:      nil,
	}
}

// EndpointRestored implements endpointmanager.Subscriber.
func (s *Server) EndpointRestored(ep *endpoint.Endpoint) {
	// No-op
}
