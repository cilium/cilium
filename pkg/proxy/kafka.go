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
	"time"

	"github.com/cilium/cilium/pkg/kafka"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
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

	conf    kafkaConfiguration
	epID    uint64
	ingress bool
	rules   policy.L7DataMap
	socket  *proxySocket
}

// ToPort returns the redirect port of an OxyRedirect
func (k *kafkaRedirect) ToPort() uint16 {
	return k.conf.listenPort
}

func (k *kafkaRedirect) IsIngress() bool {
	return k.ingress
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

func (k *kafkaRedirect) getSource() ProxySource {
	return k.conf.source
}

func apiKeyToString(apiKey int16) string {
	if key, ok := api.KafkaReverseAPIKeyMap[apiKey]; ok {
		return key
	}
	return fmt.Sprintf("%d", apiKey)
}

// kafkaLogRecord wraps an accesslog.LogRecord so that we can define methods with a receiver
type kafkaLogRecord struct {
	accesslog.LogRecord

	req *kafka.RequestMessage
}

func (k *kafkaRedirect) newKafkaLogRecord(req *kafka.RequestMessage) *kafkaLogRecord {
	record := &kafkaLogRecord{
		req: req,
		LogRecord: accesslog.LogRecord{
			Kafka: &accesslog.LogRecordKafka{
				APIVersion:    req.GetVersion(),
				APIKey:        apiKeyToString(req.GetAPIKey()),
				CorrelationID: req.GetCorrelationID(),
			},
			NodeAddressInfo: accesslog.NodeAddressInfo{
				IPv4: node.GetExternalIPv4().String(),
				IPv6: node.GetIPv6().String(),
			},
			TransportProtocol: 6, // TCP's IANA-assigned protocol number
		},
	}

	if k.IsIngress() {
		record.ObservationPoint = accesslog.Ingress
	} else {
		record.ObservationPoint = accesslog.Egress
	}

	return record
}

func (l *kafkaLogRecord) fillInfo(r Redirect, srcIPPort, dstIPPort string, srcIdentity uint32) {
	fillInfo(r, &l.LogRecord, srcIPPort, dstIPPort, srcIdentity)
}

// log Kafka log records
func (l *kafkaLogRecord) log(typ accesslog.FlowType, verdict accesslog.FlowVerdict, code int, info string) {
	l.Type = typ
	l.Verdict = verdict
	l.Kafka.ErrorCode = code
	l.Info = info
	l.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)

	log.WithFields(log.Fields{
		accesslog.FieldType:               l.Type,
		accesslog.FieldVerdict:            l.Verdict,
		accesslog.FieldCode:               l.Kafka.ErrorCode,
		accesslog.FieldKafkaAPIKey:        l.Kafka.APIKey,
		accesslog.FieldKafkaAPIVersion:    l.Kafka.APIVersion,
		accesslog.FieldKafkaCorrelationID: l.Kafka.CorrelationID,
	}).Debug("Logging Kafka L7 flow record")

	//
	// Log multiple entries for multiple Kafka topics in a single
	// request. GH #1815
	//

	topics := l.req.GetTopics()
	for i := 0; i < len(topics); i++ {
		l.Kafka.Topic.Topic = topics[i]
		l.Log()
	}
}

func (k *kafkaRedirect) handleRequest(pair *connectionPair, req *kafka.RequestMessage) {
	scopedLog := log.WithField(fieldID, pair.String())
	scopedLog.WithField(logfields.Request, req.String()).Debug("Handling Kafka request")

	record := k.newKafkaLogRecord(req)

	addr := pair.rx.conn.RemoteAddr()
	if addr == nil {
		info := fmt.Sprint("RemoteAddr() is nil")
		scopedLog.Warn(info)
		record.log(accesslog.TypeRequest, accesslog.VerdictError, kafka.ErrInvalidMessage, info)
		return
	}

	// retrieve identity of source together with original destination IP
	// and destination port
	srcIdentity, dstIPPort, err := k.conf.lookupNewDest(addr.String(), k.conf.listenPort)
	if err != nil {
		log.WithField("source",
			addr.String()).WithError(err).Error("Unable lookup original destination")
		record.log(accesslog.TypeRequest, accesslog.VerdictError, kafka.ErrInvalidMessage,
			fmt.Sprintf("Unable lookup original destination: %s", err))
		return
	}

	record.fillInfo(k, addr.String(), dstIPPort, srcIdentity)

	if !k.canAccess(req, policy.NumericIdentity(srcIdentity)) {
		scopedLog.Debug("Kafka request is denied by policy")

		record.log(accesslog.TypeRequest, accesslog.VerdictDenied,
			kafka.ErrTopicAuthorizationFailed, fmt.Sprint("Kafka request is denied by policy"))

		resp, err := req.CreateResponse(proto.ErrTopicAuthorizationFailed)
		if err != nil {
			scopedLog.WithError(err).Error("Unable to create response message")
			record.log(accesslog.TypeRequest, accesslog.VerdictError,
				kafka.ErrInvalidMessage, fmt.Sprintf("Unable to create response message: %s", err))
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

		go k.handleResponseConnection(pair, record)
	}

	scopedLog.Debug("Forwarding Kafka request")
	// log valid request
	record.log(accesslog.TypeRequest, accesslog.VerdictForwarded, kafka.ErrNone, "")

	// Write the entire raw request onto the outgoing connection
	pair.tx.Enqueue(req.GetRaw())
}

type kafkaReqMessageHander func(pair *connectionPair, req *kafka.RequestMessage)
type kafkaRespMessageHander func(pair *connectionPair, req *kafka.ResponseMessage)

func handleRequest(pair *connectionPair, c *proxyConnection,
	record *kafkaLogRecord, handler kafkaReqMessageHander) {
	for {
		req, err := kafka.ReadRequest(c.conn)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				c.Close()
				return
			}

			if record != nil {
				record.log(accesslog.TypeRequest, accesslog.VerdictError,
					kafka.ErrInvalidMessage, fmt.Sprintf("Unable to parse Kafka request: %s", err))
			}

			log.WithError(err).Error("Unable to parse Kafka request")
			continue
		} else {
			handler(pair, req)
		}
	}
}

func handleResponse(pair *connectionPair, c *proxyConnection,
	record *kafkaLogRecord, handler kafkaRespMessageHander) {
	for {
		rsp, err := kafka.ReadResponse(c.conn)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				c.Close()
				return
			}

			if record != nil {
				record.log(accesslog.TypeResponse, accesslog.VerdictError,
					kafka.ErrInvalidMessage,
					fmt.Sprintf("Unable to parse Kafka response: %s", err))
			}

			log.WithError(err).Error("Unable to parse Kafka response")
			continue
		} else {
			handler(pair, rsp)
		}
	}
}

func (k *kafkaRedirect) handleRequestConnection(pair *connectionPair) {
	log.WithFields(log.Fields{
		"from": pair.rx,
		"to":   pair.tx,
	}).Debug("Proxying request Kafka connection")

	handleRequest(pair, pair.rx, nil, k.handleRequest)
}

func (k *kafkaRedirect) handleResponseConnection(pair *connectionPair,
	record *kafkaLogRecord) {
	log.WithFields(log.Fields{
		"from": pair.tx,
		"to":   pair.rx,
	}).Debug("Proxying response Kafka connection")

	handleResponse(pair, pair.tx, record, func(pair *connectionPair,
		rsp *kafka.ResponseMessage) {
		pair.rx.Enqueue(rsp.GetRaw())
	})

	// log valid response
	record.log(accesslog.TypeResponse, accesslog.VerdictForwarded, kafka.ErrNone, "")
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
