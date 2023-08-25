// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package pool

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/connectivity"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	peerTypes "github.com/cilium/cilium/pkg/hubble/peer/types"
	poolTypes "github.com/cilium/cilium/pkg/hubble/relay/pool/types"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
)

type peer struct {
	mu lock.Mutex
	peerTypes.Peer
	conn            poolTypes.ClientConn
	connAttempts    int
	nextConnAttempt time.Time
}

// PeerManager manages a pool of peers (Peer) and associated gRPC connections.
// Peers and peer change notifications are obtained from a peer gRPC service.
type PeerManager struct {
	opts    options
	offline chan string
	wg      sync.WaitGroup
	stop    chan struct{}
	mu      lock.RWMutex
	peers   map[string]*peer
}

// NewPeerManager creates a new manager that connects to a peer gRPC service to
// manage peers and a connection to every peer's gRPC API.
func NewPeerManager(options ...Option) (*PeerManager, error) {
	opts := defaultOptions
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, fmt.Errorf("failed to apply option: %v", err)
		}
	}
	return &PeerManager{
		peers:   make(map[string]*peer),
		offline: make(chan string, 100),
		stop:    make(chan struct{}),
		opts:    opts,
	}, nil
}

// Start starts the manager.
func (m *PeerManager) Start() {
	m.wg.Add(2)
	go func() {
		defer m.wg.Done()
		m.watchNotifications()
	}()
	go func() {
		defer m.wg.Done()
		m.manageConnections()
	}()
}

func (m *PeerManager) watchNotifications() {
	ctx, cancel := context.WithCancel(context.Background())
	retryTimer, retryTimerDone := inctimer.New()
	defer retryTimerDone()
connect:
	for {
		cl, err := m.opts.peerClientBuilder.Client(m.opts.peerServiceAddress)
		if err != nil {
			m.opts.log.WithFields(logrus.Fields{
				"error":  err,
				"target": m.opts.peerServiceAddress,
			}).Warning("Failed to create peer client for peers synchronization; will try again after the timeout has expired")
			select {
			case <-m.stop:
				cancel()
				return
			case <-retryTimer.After(m.opts.retryTimeout):
				continue
			}
		}
		client, err := cl.Notify(ctx, &peerpb.NotifyRequest{})
		if err != nil {
			cl.Close()
			m.opts.log.WithFields(logrus.Fields{
				"error":              err,
				"connection timeout": m.opts.retryTimeout,
			}).Warning("Failed to create peer notify client for peers change notification; will try again after the timeout has expired")
			select {
			case <-m.stop:
				cancel()
				return
			case <-retryTimer.After(m.opts.retryTimeout):
				continue
			}
		}
		for {
			select {
			case <-m.stop:
				cl.Close()
				cancel()
				return
			default:
			}
			cn, err := client.Recv()
			if err != nil {
				cl.Close()
				m.opts.log.WithFields(logrus.Fields{
					"error":              err,
					"connection timeout": m.opts.retryTimeout,
				}).Warning("Error while receiving peer change notification; will try again after the timeout has expired")
				select {
				case <-m.stop:
					cancel()
					return
				case <-retryTimer.After(m.opts.retryTimeout):
					continue connect
				}
			}
			m.opts.log.WithField("change notification", cn).Info("Received peer change notification")
			p := peerTypes.FromChangeNotification(cn)
			switch cn.GetType() {
			case peerpb.ChangeNotificationType_PEER_ADDED:
				m.add(p)
			case peerpb.ChangeNotificationType_PEER_DELETED:
				m.remove(p)
			case peerpb.ChangeNotificationType_PEER_UPDATED:
				m.update(p)
			}
		}
	}
}

func (m *PeerManager) manageConnections() {
	connTimer, connTimerDone := inctimer.New()
	defer connTimerDone()
	for {
		select {
		case <-m.stop:
			return
		case name := <-m.offline:
			m.mu.RLock()
			p := m.peers[name]
			m.mu.RUnlock()
			m.wg.Add(1)
			go func(p *peer) {
				defer m.wg.Done()
				// a connection request has been made, make sure to attempt a connection
				m.connect(p, true)
			}(p)
		case <-connTimer.After(m.opts.connCheckInterval):
			m.mu.RLock()
			now := time.Now()
			for _, p := range m.peers {
				p.mu.Lock()
				if p.conn != nil {
					switch p.conn.GetState() {
					case connectivity.Connecting, connectivity.Idle, connectivity.Ready, connectivity.Shutdown:
						p.mu.Unlock()
						continue
					}
				}
				switch {
				case p.nextConnAttempt.IsZero(), p.nextConnAttempt.Before(now):
					p.mu.Unlock()
					m.wg.Add(1)
					go func(p *peer) {
						defer m.wg.Done()
						m.connect(p, false)
					}(p)
				default:
					p.mu.Unlock()
				}
			}
			m.mu.RUnlock()
		}
	}
}

// Stop stops the manager.
func (m *PeerManager) Stop() {
	close(m.stop)
	m.wg.Wait()
}

// List implements observer.PeerLister.List.
func (m *PeerManager) List() []poolTypes.Peer {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.peers) == 0 {
		return nil
	}
	peers := make([]poolTypes.Peer, 0, len(m.peers))
	for _, v := range m.peers {
		// note: there shouldn't be null entries in the map
		peers = append(peers, poolTypes.Peer{
			Peer: peerTypes.Peer{
				Name:          v.Name,
				Address:       v.Address,
				TLSEnabled:    v.TLSEnabled,
				TLSServerName: v.TLSServerName,
			},
			Conn: v.conn,
		})
	}
	return peers
}

// ReportOffline implements observer.PeerReporter.ReportOffline.
func (m *PeerManager) ReportOffline(name string) {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.mu.RLock()
		p, ok := m.peers[name]
		m.mu.RUnlock()
		if !ok {
			return
		}
		p.mu.Lock()
		if p.conn != nil {
			switch p.conn.GetState() {
			case connectivity.Connecting, connectivity.Idle, connectivity.Ready:
				// it looks like it's actually online or being brought online
				p.mu.Unlock()
				return
			}
		}
		p.mu.Unlock()
		select {
		case <-m.stop:
		case m.offline <- name:
		}
	}()
}

func (m *PeerManager) add(hp *peerTypes.Peer) {
	if hp == nil {
		return
	}
	p := &peer{Peer: *hp}
	m.mu.Lock()
	m.peers[p.Name] = p
	m.mu.Unlock()
	select {
	case <-m.stop:
	case m.offline <- p.Name:
	}
}

func (m *PeerManager) remove(hp *peerTypes.Peer) {
	if hp == nil {
		return
	}
	m.mu.Lock()
	if p, ok := m.peers[hp.Name]; ok {
		m.disconnect(p)
		delete(m.peers, hp.Name)
	}
	m.mu.Unlock()
}

func (m *PeerManager) update(hp *peerTypes.Peer) {
	if hp == nil {
		return
	}
	p := &peer{Peer: *hp}
	m.mu.Lock()
	if old, ok := m.peers[p.Name]; ok {
		m.disconnect(old)
	}
	m.peers[p.Name] = p
	m.mu.Unlock()
	select {
	case <-m.stop:
	case m.offline <- p.Name:
	}
}

func (m *PeerManager) connect(p *peer, ignoreBackoff bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.Address == nil || (p.nextConnAttempt.After(now) && !ignoreBackoff) {
		return
	}
	if p.conn != nil {
		switch p.conn.GetState() {
		case connectivity.Connecting, connectivity.Idle, connectivity.Ready:
			return // no need to attempt to connect
		default:
			if err := p.conn.Close(); err != nil {
				m.opts.log.WithFields(logrus.Fields{
					"error": err,
					"peer":  p.Name,
				}).Warning("Failed to properly close gRPC client connection")
			}
			p.conn = nil
		}
	}

	scopedLog := m.opts.log.WithFields(logrus.Fields{
		"address":    p.Address,
		"hubble-tls": p.TLSEnabled,
		"peer":       p.Name,
	})

	scopedLog.Info("Connecting")
	conn, err := m.opts.clientConnBuilder.ClientConn(p.Address.String(), p.TLSServerName)
	if err != nil {
		duration := m.opts.backoff.Duration(p.connAttempts)
		p.nextConnAttempt = now.Add(duration)
		p.connAttempts++
		scopedLog.WithFields(logrus.Fields{
			"error":       err,
			"next-try-in": duration,
		}).Warning("Failed to create gRPC client")
	} else {
		p.nextConnAttempt = time.Time{}
		p.connAttempts = 0
		p.conn = conn
		scopedLog.Info("Connected")
	}
}

func (m *PeerManager) disconnect(p *peer) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil {
		return
	}

	scopedLog := m.opts.log.WithFields(logrus.Fields{
		"address":    p.Address,
		"hubble-tls": p.TLSEnabled,
		"peer":       p.Name,
	})

	scopedLog.Info("Disconnecting")
	if err := p.conn.Close(); err != nil {
		scopedLog.WithField("error", err).Warning("Failed to properly close gRPC client connection")
	}
	p.conn = nil
	scopedLog.Info("Disconnected")
}
