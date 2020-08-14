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
	"sync"
	"time"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	peerTypes "github.com/cilium/cilium/pkg/hubble/peer/types"
	poolTypes "github.com/cilium/cilium/pkg/hubble/relay/pool/types"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/connectivity"
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
			case <-time.After(m.opts.retryTimeout):
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
			case <-time.After(m.opts.retryTimeout):
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
				case <-time.After(m.opts.retryTimeout):
					continue connect
				}
			}
			m.opts.log.WithField("change notification", cn).Debug("Received peer change notification")
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
	for {
		select {
		case <-m.stop:
			return
		case name := <-m.offline:
			m.mu.RLock()
			p := m.peers[name]
			m.mu.RUnlock()
			m.wg.Add(1)
			go func() {
				defer m.wg.Done()
				// a connection request has been made, make sure to attempt a connection
				m.connect(p, true)
			}()
		case <-time.After(m.opts.connCheckInterval):
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
					go func() {
						defer m.wg.Done()
						m.connect(p, false)
					}()
				default:
					p.mu.Unlock()
				}
			}
			m.mu.RUnlock()
		}
	}
}

// Stop stops the manaager.
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
				Name:    v.Name,
				Address: v.Address,
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
				}).Warningf("Failed to properly close gRPC client connection to peer %s", p.Name)
			}
			p.conn = nil
		}
	}

	m.opts.log.WithFields(logrus.Fields{
		"address": p.Address,
	}).Debugf("Connecting peer %s...", p.Name)
	//FIXME: provide hostname to ClientConn
	conn, err := m.opts.clientConnBuilder.ClientConn(p.Address.String(), "")
	if err != nil {
		duration := m.opts.backoff.Duration(p.connAttempts)
		p.nextConnAttempt = now.Add(duration)
		p.connAttempts++
		m.opts.log.WithFields(logrus.Fields{
			"address": p.Address,
			"error":   err,
		}).Warningf("Failed to create gRPC client connection to peer %s; next attempt after %s", p.Name, duration)
	} else {
		p.nextConnAttempt = time.Time{}
		p.connAttempts = 0
		p.conn = conn
		m.opts.log.Debugf("Peer %s connected", p.Name)
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
	m.opts.log.Debugf("Disconnecting peer %s...", p.Name)
	if err := p.conn.Close(); err != nil {
		m.opts.log.WithFields(logrus.Fields{
			"error": err,
		}).Warningf("Failed to properly close gRPC client connection to peer %s", p.Name)
	}
	p.conn = nil
	m.opts.log.Debugf("Peer %s disconnected", p.Name)
}
