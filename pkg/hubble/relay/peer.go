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

package relay

import (
	"context"
	"time"

	peerpb "github.com/cilium/cilium/api/v1/peer"
	"github.com/cilium/cilium/pkg/hubble/peer"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func newConn(target string, dialTimeout time.Duration, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	return grpc.DialContext(ctx, target, opts...)
}

func newPeerClient(target string, dialTimeout time.Duration) (peerpb.PeerClient, *grpc.ClientConn, error) {
	// the connection is assumed to be local
	conn, err := newConn(target, dialTimeout, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		return nil, nil, err
	}
	return peerpb.NewPeerClient(conn), conn, nil
}

type peerSyncer interface {
	Start()
	Stop()
	List() []hubblePeer
	ConnectPeer(name, address string)
}

type syncer struct {
	target       string
	dialTimeout  time.Duration
	retryTimeout time.Duration
	log          logrus.FieldLogger
	peers        map[string]*hubblePeer
	mu           lock.Mutex
	stop         chan struct{}
}

func newSyncer(target string, dialTimeout, retryTimeout time.Duration, logger logrus.FieldLogger) *syncer {
	return &syncer{
		target:       target,
		dialTimeout:  dialTimeout,
		retryTimeout: retryTimeout,
		log:          logger,
		peers:        make(map[string]*hubblePeer),
		stop:         make(chan struct{}),
	}
}

func (s *syncer) Start() {
	go func() {
		ctx, cancel := context.WithCancel(context.Background())
	connect:
		for {
			cl, conn, err := newPeerClient(s.target, s.dialTimeout)
			if err != nil {
				s.log.WithFields(logrus.Fields{
					"error":        err,
					"dial timeout": s.dialTimeout,
				}).Warning("Failed to create peer client for peers synchronization; will try again after the timeout has expired")
				select {
				case <-s.stop:
					cancel()
					return
				case <-time.After(s.retryTimeout):
					continue
				}
			}
			client, err := cl.Notify(ctx, &peerpb.NotifyRequest{})
			if err != nil {
				conn.Close()
				s.log.WithFields(logrus.Fields{
					"error":              err,
					"connection timeout": s.retryTimeout,
				}).Warning("Failed to create peer notify client for peers change notification; will try again after the timeout has expired")
				select {
				case <-s.stop:
					cancel()
					return
				case <-time.After(s.retryTimeout):
					continue
				}
			}
			for {
				select {
				case <-s.stop:
					conn.Close()
					cancel()
					return
				default:
				}
				cn, err := client.Recv()
				if err != nil {
					conn.Close()
					s.log.WithFields(logrus.Fields{
						"error":              err,
						"connection timeout": s.retryTimeout,
					}).Warning("Error while receiving peer change notification; will try again after the timeout has expired")
					select {
					case <-s.stop:
						cancel()
						return
					case <-time.After(s.retryTimeout):
						continue connect
					}
				}
				s.log.WithField("change notification", cn).Debug("Received peer change notification")
				p := peer.FromChangeNotification(cn)
				switch cn.GetType() {
				case peerpb.ChangeNotificationType_PEER_ADDED:
					s.addPeer(p)
				case peerpb.ChangeNotificationType_PEER_DELETED:
					s.deletePeer(p)
				case peerpb.ChangeNotificationType_PEER_UPDATED:
					s.updatePeer(p)
				}
			}
		}
	}()
}

func (s *syncer) Stop() {
	close(s.stop)
}

func (s *syncer) ConnectPeer(name, addr string) {
	// we don't want to block the caller while waiting to establish a
	// connection; connect in the background
	go func() {
		s.log.WithFields(logrus.Fields{
			"address":      addr,
			"dial timeout": s.dialTimeout,
		}).Debugf("Connecting peer %s...", name)

		//FIXME: remove WithInsecure once mutual TLS is implemented
		conn, connErr := newConn(addr, s.dialTimeout, grpc.WithInsecure(), grpc.WithBlock())
		var err error
		s.mu.Lock()
		if hp, ok := s.peers[name]; ok {
			if hp.conn != nil { // make sure to close existing connection, if any
				err = hp.conn.Close()
			}
			hp.conn = conn
			hp.connErr = connErr
		}
		s.mu.Unlock()

		if err != nil {
			s.log.WithFields(logrus.Fields{
				"error": err,
			}).Warningf("Failed to properly close gRPC client connection to peer %s", name)
		}
		if connErr != nil {
			s.log.WithFields(logrus.Fields{
				"address":      addr,
				"dial timeout": s.dialTimeout,
				"error":        connErr,
			}).Warningf("Failed to create gRPC client connection to peer %s", name)
		} else {
			s.log.Debugf("Peer %s connected", name)
		}
	}()
}

func (s *syncer) disconnectPeer(name string) {
	s.log.Debugf("Disconnecting peer %s...", name)

	var err error
	s.mu.Lock()
	if hp, ok := s.peers[name]; ok && hp.conn != nil {
		err = hp.conn.Close()
		hp.conn = nil
	}
	s.mu.Unlock()

	if err != nil {
		s.log.WithFields(logrus.Fields{
			"error": err,
		}).Warningf("Failed to properly close gRPC client connection to peer %s", name)
	}
	s.log.Debugf("Peer %s disconnected", name)
}

func (s *syncer) addPeer(p *peer.Peer) {
	if p == nil {
		return
	}

	hp := &hubblePeer{*p, nil, nil}
	s.mu.Lock()
	s.peers[p.Name] = hp
	s.mu.Unlock()

	s.ConnectPeer(p.Name, p.Address.String())
}

func (s *syncer) deletePeer(p *peer.Peer) {
	if p == nil {
		return
	}

	s.disconnectPeer(p.Name)
	s.mu.Lock()
	delete(s.peers, p.Name)
	s.mu.Unlock()
}

func (s *syncer) updatePeer(p *peer.Peer) {
	if p == nil {
		return
	}

	s.disconnectPeer(p.Name)
	s.addPeer(p)
}

func (s *syncer) List() []hubblePeer {
	s.mu.Lock()
	p := make([]hubblePeer, 0, len(s.peers))
	for _, v := range s.peers {
		// note: there shouldn't be null entries in the map
		p = append(p, *v)
	}
	s.mu.Unlock()
	return p
}
