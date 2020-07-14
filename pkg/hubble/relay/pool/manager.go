// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pool

import (
	"context"
	"fmt"
	"time"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	hubblePeer "github.com/cilium/cilium/pkg/hubble/peer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/connectivity"
)

// PeerManager defines the functions a peer manager must implement when
// handling peers and respective connections.
type PeerManager interface {
	// Start instructs the manager to start peer change notification handling
	// and connection management.
	Start()
	// Stop stops any peer manager activity.
	Stop()
	// List returns a list of peers with active connections. If a peer cannot
	// be connected to; its Conn attribute must be nil.
	List() []Peer
	// ReportOffline allows the caller to report a peer as being offline. The
	// peer is identified by its name.
	ReportOffline(name string)
}

// Peer is like hubblePeer.Peer but includes a Conn attribute to reach the
// peer's gRPC API endpoint.
type Peer struct {
	hubblePeer.Peer
	Conn ClientConn
}

type peer struct {
	hubblePeer.Peer
	conn            ClientConn
	connAttempts    int
	nextConnAttempt time.Time
	mu              lock.Mutex
}

// Manager implements the PeerManager interface.
type Manager struct {
	log     logrus.FieldLogger
	peers   map[string]*peer
	offline chan string
	mu      lock.Mutex
	opts    Options
	stop    chan struct{}
}

// ensure that Manager implements the PeerManager interface.
var _ PeerManager = (*Manager)(nil)

// NewManager creates a new manager that connects to a peer gRPC service using
// target to manage peers and a connection to every peer's gRPC API.
func NewManager(options ...Option) (*Manager, error) {
	opts := DefaultOptions
	for _, opt := range options {
		if err := opt(&opts); err != nil {
			return nil, fmt.Errorf("failed to apply option: %v", err)
		}
	}
	logger := logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble-relay")
	logging.ConfigureLogLevel(opts.Debug)
	return &Manager{
		peers:   make(map[string]*peer),
		offline: make(chan string, 100),
		log:     logger,
		stop:    make(chan struct{}),
		opts:    opts,
	}, nil
}

// Start implements PeerManager.Start.
func (m *Manager) Start() {
	go m.watchNotifications()
	go m.manageConnections()
}

func (m *Manager) watchNotifications() {
	ctx, cancel := context.WithCancel(context.Background())
connect:
	for {
		cl, err := m.opts.PeerClientBuilder.Client()
		if err != nil {
			m.log.WithFields(logrus.Fields{
				"error":  err,
				"target": m.opts.PeerClientBuilder.Target(),
			}).Warning("Failed to create peer client for peers synchronization; will try again after the timeout has expired")
			select {
			case <-m.stop:
				cancel()
				return
			case <-time.After(m.opts.RetryTimeout):
				continue
			}
		}
		client, err := cl.Notify(ctx, &peerpb.NotifyRequest{})
		if err != nil {
			cl.Close()
			m.log.WithFields(logrus.Fields{
				"error":              err,
				"connection timeout": m.opts.RetryTimeout,
			}).Warning("Failed to create peer notify client for peers change notification; will try again after the timeout has expired")
			select {
			case <-m.stop:
				cancel()
				return
			case <-time.After(m.opts.RetryTimeout):
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
				m.log.WithFields(logrus.Fields{
					"error":              err,
					"connection timeout": m.opts.RetryTimeout,
				}).Warning("Error while receiving peer change notification; will try again after the timeout has expired")
				select {
				case <-m.stop:
					cancel()
					return
				case <-time.After(m.opts.RetryTimeout):
					continue connect
				}
			}
			m.log.WithField("change notification", cn).Debug("Received peer change notification")
			p := hubblePeer.FromChangeNotification(cn)
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

func (m *Manager) manageConnections() {
	for {
		select {
		case <-m.stop:
			return
		case name := <-m.offline:
			m.mu.Lock()
			p := m.peers[name]
			m.mu.Unlock()
			m.connect(p)
		case <-time.After(30 * time.Second): //FIXME: make this configurable
			var retry []*peer
			m.mu.Lock()
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
				if p.nextConnAttempt.IsZero() || p.nextConnAttempt.Before(now) {
					retry = append(retry, p)
				}
				p.mu.Unlock()
			}
			m.mu.Unlock()
			for _, p := range retry {
				m.disconnect(p)
				m.connect(p)
			}
		}
	}
}

// Stop implements PeerManager.Stop.
func (m *Manager) Stop() {
	close(m.stop)
}

// List implements PeerManager.List.
func (m *Manager) List() []Peer {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.peers) == 0 {
		return nil
	}
	peers := make([]Peer, 0, len(m.peers))
	for _, v := range m.peers {
		// note: there shouldn't be null entries in the map
		peers = append(peers, Peer{
			Peer: hubblePeer.Peer{
				Name:    v.Name,
				Address: v.Address,
			},
			Conn: v.conn,
		})
	}
	return peers
}

// ReportOffline implements PeerManager.ReportOffline.
func (m *Manager) ReportOffline(name string) {
	go func() {
		m.mu.Lock()
		p, ok := m.peers[name]
		m.mu.Unlock()
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

func (m *Manager) add(hp *hubblePeer.Peer) {
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

func (m *Manager) remove(hp *hubblePeer.Peer) {
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

func (m *Manager) update(hp *hubblePeer.Peer) {
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

func (m *Manager) connect(p *peer) {
	go func() {
		if p == nil {
			return
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		now := time.Now()
		if p.nextConnAttempt.After(now) {
			return
		}
		if p.conn != nil {
			switch p.conn.GetState() {
			case connectivity.Connecting, connectivity.Idle, connectivity.Ready:
				return // no need to attempt to connect
			default:
				if err := p.conn.Close(); err != nil {
					m.log.WithFields(logrus.Fields{
						"error": err,
					}).Warningf("Failed to properly close gRPC client connection to peer %s", p.Name)
				}
				p.conn = nil
			}
		}

		m.log.WithFields(logrus.Fields{
			"address": p.Address,
		}).Debugf("Connecting peer %s...", p.Name)
		conn, err := m.opts.ClientConnBuilder.ClientConn(p.Address.String())
		if err != nil {
			duration := m.opts.Backoff.Duration(p.connAttempts)
			p.nextConnAttempt = now.Add(duration)
			p.connAttempts++
			m.log.WithFields(logrus.Fields{
				"address": p.Address,
				"error":   err,
			}).Warningf("Failed to create gRPC client connection to peer %s; next attempt after %s", p.Name, duration)
		} else {
			p.nextConnAttempt = time.Time{}
			p.connAttempts = 0
			p.conn = conn
			m.log.Debugf("Peer %s connected", p.Name)
		}
	}()
}

func (m *Manager) disconnect(p *peer) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil {
		return
	}
	m.log.Debugf("Disconnecting peer %s...", p.Name)
	if err := p.conn.Close(); err != nil {
		m.log.WithFields(logrus.Fields{
			"error": err,
		}).Warningf("Failed to properly close gRPC client connection to peer %s", p.Name)
	}
	p.conn = nil
	m.log.Debugf("Peer %s disconnected", p.Name)
}
