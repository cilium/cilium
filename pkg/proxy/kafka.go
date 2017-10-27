// Copyright 2017 Authors of Cilium
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

package proxy

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/cilium/cilium/pkg/kafka"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/nodeaddress"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"

	"github.com/optiopay/kafka/proto"
	log "github.com/sirupsen/logrus"
)

const (
	fieldID = "id"
)

// kafkaRedirect implements the Redirect interface for an l7 proxy
type kafkaRedirect struct {
	// protects all fields of this struct
	lock.RWMutex

	conf     kafkaConfiguration
	epID     uint64
	ingress  bool
	nodeInfo accesslog.NodeAddressInfo
	rules    policy.L7DataMap
	socket   *proxySocket
}

// ToPort returns the redirect port of an OxyRedirect
func (k *kafkaRedirect) ToPort() uint16 {
	return k.conf.listenPort
}

type destLookupFunc func(remoteAddr string, dport uint16) (uint32, string, error)

type kafkaConfiguration struct {
	policy        *policy.L4Filter
	id            string
	source        ProxySource
	listenPort    uint16
	noMarker      bool
	lookupNewDest destLookupFunc
}

// createKafkaRedirect creates a redirect with corresponding proxy
// configuration. This will launch a proxy instance.
func createKafkaRedirect(conf kafkaConfiguration) (Redirect, error) {
	redir := &kafkaRedirect{
		conf:    conf,
		epID:    conf.source.GetID(),
		ingress: conf.policy.Ingress,
		nodeInfo: accesslog.NodeAddressInfo{
			IPv4: nodeaddress.GetExternalIPv4().String(),
			IPv6: nodeaddress.GetIPv6().String(),
		},
	}

	if redir.conf.lookupNewDest == nil {
		redir.conf.lookupNewDest = lookupNewDest
	}

	if err := redir.UpdateRules(conf.policy); err != nil {
		return nil, err
	}

	marker := 0
	if !conf.noMarker {
		marker = GetMagicMark(redir.ingress)

		// As ingress proxy, all replies to incoming requests must have the
		// identity of the endpoint we are proxying for
		if redir.ingress {
			marker |= int(conf.source.GetIdentity())
		}
	}

	// Listen needs to be in the synchronous part of this function to ensure that
	// the proxy port is never refusing connections.
	socket, err := listenSocket(fmt.Sprintf(":%d", redir.conf.listenPort), marker)
	if err != nil {
		return nil, err
	}

	redir.socket = socket

	go func() {
		for {
			pair, err := socket.Accept()
			select {
			case <-socket.closing:
				// Don't report errors while the socket is being closed
				return
			default:
				if err != nil {
					log.WithField(logfields.Port, redir.conf.listenPort).WithError(err).Error("Unable to accept connection on port")
					continue
				}
			}

			go redir.handleRequestConnection(pair)
		}
	}()

	return redir, nil
}

func (k *kafkaRedirect) canAccess(req *kafka.RequestMessage, numIdentity policy.NumericIdentity) bool {
	var identity *policy.Identity

	if numIdentity != 0 {
		identity = k.conf.source.ResolveIdentity(numIdentity)
		if identity == nil {
			log.WithFields(log.Fields{
				logfields.Request:  req.String(),
				logfields.Identity: numIdentity,
			}).Warn("Unable to resolve identity to labels")
		}
	}

	rules := k.rules.GetRelevantRules(identity)

	if rules.Kafka == nil {
		log.WithField(logfields.Request, req.String()).Debug("Allowing, no Kafka rules loaded")

		return true
	}

	b, err := json.Marshal(rules.Kafka)
	if err != nil {
		log.WithError(err).WithField(logfields.Request, req.String()).Debug("Error marshalling kafka rules to apply")
	} else {
		log.WithFields(log.Fields{
			logfields.Request: req.String(),
			"rule":            string(b),
		}).Debug("Applying rule")
	}

	return req.MatchesRule(rules.Kafka)
}

func (k *kafkaRedirect) handleRequest(pair *connectionPair, req *kafka.RequestMessage) {
	scopedLog := log.WithField(fieldID, pair.String())
	scopedLog.WithField(logfields.Request, req.String()).Debug("Handling Kafka request")

	addr := pair.rx.conn.RemoteAddr()
	if addr == nil {
		scopedLog.Warn("RemoteAddr() is nil")
		return
	}

	// retrieve identity of source together with original destination IP
	// and destination port
	srcIdentity, dstIPPort, err := k.conf.lookupNewDest(addr.String(), k.conf.listenPort)
	if err != nil {
		log.WithField("source", addr.String()).WithError(err).Error("Unable lookup original destination")
		return
	}

	if !k.canAccess(req, policy.NumericIdentity(srcIdentity)) {
		scopedLog.Debug("Kafka request is denied by policy")

		resp, err := req.CreateResponse(proto.ErrTopicAuthorizationFailed)
		if err != nil {
			scopedLog.WithError(err).Error("Unable to create response message")
			return
		}

		pair.rx.Enqueue(resp.GetRaw())
		return
	}

	if pair.tx.Closed() {
		marker := 0
		if !k.conf.noMarker {
			marker = GetMagicMark(k.ingress) | int(srcIdentity)
		}

		scopedLog.WithFields(log.Fields{
			"marker":      marker,
			"destination": dstIPPort,
		}).Debug("Dialing original destination")

		txConn, err := ciliumDialer(marker, addr.Network(), dstIPPort)
		if err != nil {
			scopedLog.WithError(err).WithFields(log.Fields{
				"origNetwork": addr.Network(),
				"origDest":    dstIPPort,
			}).Error("Unable to dial original destination")
			return
		}

		pair.tx.SetConnection(txConn)
		go k.handleResponseConnection(pair)
	}

	scopedLog.Debug("Forwarding Kafka request")

	// Write the entire raw request onto the outgoing connection
	pair.tx.Enqueue(req.GetRaw())
}

type kafkaMessageHander func(pair *connectionPair, req *kafka.RequestMessage)

func handleConnection(pair *connectionPair, c *proxyConnection, handler kafkaMessageHander) {
	for {
		req, err := kafka.ReadRequest(c.conn)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				c.Close()
				return
			}

			log.WithError(err).Error("Unable to parse Kafka request")
			continue
		} else {
			handler(pair, req)
		}
	}
}

func (k *kafkaRedirect) handleRequestConnection(pair *connectionPair) {
	log.WithFields(log.Fields{
		"from": pair.rx,
		"to":   pair.tx,
	}).Debug("Proxying request Kafka connection")

	handleConnection(pair, pair.rx, k.handleRequest)
}

func (k *kafkaRedirect) handleResponseConnection(pair *connectionPair) {
	log.WithFields(log.Fields{
		"from": pair.tx,
		"to":   pair.rx,
	}).Debug("Proxying response Kafka connection")

	handleConnection(pair, pair.tx, func(pair *connectionPair, req *kafka.RequestMessage) {
		pair.rx.Enqueue(req.GetRaw())
	})
}

// UpdateRules replaces old l7 rules of a redirect with new ones.
func (k *kafkaRedirect) UpdateRules(l4 *policy.L4Filter) error {
	if l4.L7Parser != policy.ParserTypeKafka {
		return fmt.Errorf("invalid type %q, must be of type ParserTypeKafka", l4.L7Parser)
	}

	k.Lock()
	k.rules = policy.L7DataMap{}
	for key, val := range l4.L7RulesPerEp {
		k.rules[key] = val
	}
	k.Unlock()

	return nil
}

// Close the redirect.
func (k *kafkaRedirect) Close() {
	k.socket.Close()
}

func init() {
	if err := proto.ConfigureParser(proto.ParserConfig{
		SimplifiedMessageSetParsing: false,
	}); err != nil {
		log.WithError(err).Fatal("Unable to configure kafka parser")
	}
}
