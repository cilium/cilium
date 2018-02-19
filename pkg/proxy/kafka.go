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
	"time"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/kafka"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"

	"github.com/optiopay/kafka/proto"
	"github.com/sirupsen/logrus"
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

	if err := redir.UpdateRules(conf.policy, nil); err != nil {
		return nil, err
	}

	marker := 0
	if !conf.noMarker {
		markIdentity := int(0)
		// As ingress proxy, all replies to incoming requests must have the
		// identity of the endpoint we are proxying for
		if redir.ingress {
			markIdentity = int(conf.source.GetIdentity())
		}

		marker = GetMagicMark(redir.ingress, markIdentity)
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
			pair, err := socket.Accept(true)
			select {
			case <-socket.closing:
				// Don't report errors while the socket is being closed
				return
			default:
			}

			if err != nil {
				log.WithField(logfields.Port, redir.conf.listenPort).WithError(err).Error("Unable to accept connection on port")
				continue
			}

			go redir.handleRequestConnection(pair)
		}
	}()

	return redir, nil
}

func (k *kafkaRedirect) canAccess(req *kafka.RequestMessage, numIdentity policy.NumericIdentity) bool {
	var identity *policy.Identity

	if numIdentity != 0 {
		identity = policy.LookupIdentityByID(numIdentity)
		if identity == nil {
			log.WithFields(logrus.Fields{
				logfields.Request:  req.String(),
				logfields.Identity: numIdentity,
			}).Warn("Unable to resolve identity to labels")
		}
	}

	rules := k.rules.GetRelevantRules(identity)

	if rules.Kafka == nil {
		flowdebug.Log(log.WithField(logfields.Request, req.String()),
			"No Kafka rules loaded, rejecting")
		return false
	}

	b, err := json.Marshal(rules.Kafka)
	if err != nil {
		flowdebug.Log(log.WithError(err).WithField(logfields.Request, req.String()),
			"Error marshalling kafka rules to apply")
		return false
	} else {
		flowdebug.Log(log.WithFields(logrus.Fields{
			logfields.Request: req.String(),
			"rule":            string(b),
		}), "Applying rule")
	}

	return req.MatchesRule(rules.Kafka)
}

func (k *kafkaRedirect) getSource() ProxySource {
	return k.conf.source
}

// kafkaLogRecord wraps an accesslog.LogRecord so that we can define methods with a receiver
type kafkaLogRecord struct {
	accesslog.LogRecord
	req *kafka.RequestMessage
}

func (k *kafkaRedirect) newKafkaLogRecord(req *kafka.RequestMessage) kafkaLogRecord {
	record := kafkaLogRecord{
		LogRecord: req.GetLogRecord(),
		req:       req,
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

	l.LogRecord.NodeAddressInfo = accesslog.NodeAddressInfo{
		IPv4: node.GetExternalIPv4().String(),
		IPv6: node.GetIPv6().String(),
	}

	flowdebug.Log(log.WithFields(logrus.Fields{
		accesslog.FieldType:               l.Type,
		accesslog.FieldVerdict:            l.Verdict,
		accesslog.FieldCode:               l.Kafka.ErrorCode,
		accesslog.FieldKafkaAPIKey:        l.Kafka.APIKey,
		accesslog.FieldKafkaAPIVersion:    l.Kafka.APIVersion,
		accesslog.FieldKafkaCorrelationID: l.Kafka.CorrelationID,
	}), "Logging Kafka L7 flow record")

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
	flowdebug.Log(scopedLog.WithField(logfields.Request, req.String()), "Handling Kafka request")

	record := k.newKafkaLogRecord(req)

	addr := pair.Rx.conn.RemoteAddr()
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
		scopedLog.WithField("source",
			addr.String()).WithError(err).Error("Unable lookup original destination")
		record.log(accesslog.TypeRequest, accesslog.VerdictError, kafka.ErrInvalidMessage,
			fmt.Sprintf("Unable lookup original destination: %s", err))
		return
	}

	record.fillInfo(k, addr.String(), dstIPPort, srcIdentity)

	if !k.canAccess(req, policy.NumericIdentity(srcIdentity)) {
		flowdebug.Log(scopedLog, "Kafka request is denied by policy")

		record.log(accesslog.TypeRequest, accesslog.VerdictDenied,
			kafka.ErrTopicAuthorizationFailed, fmt.Sprint("Kafka request is denied by policy"))

		resp, err := req.CreateResponse(proto.ErrTopicAuthorizationFailed)
		if err != nil {
			record.log(accesslog.TypeRequest, accesslog.VerdictError,
				kafka.ErrInvalidMessage, fmt.Sprintf("Unable to create response: %s", err))
			scopedLog.WithError(err).Error("Unable to create Kafka response")
			return
		}

		pair.Rx.Enqueue(resp.GetRaw())
		return
	}

	if pair.Tx.Closed() {
		marker := 0
		if !k.conf.noMarker {
			marker = GetMagicMark(k.ingress, int(srcIdentity))
		}

		flowdebug.Log(scopedLog.WithFields(logrus.Fields{
			"marker":      marker,
			"destination": dstIPPort,
		}), "Dialing original destination")

		txConn, err := ciliumDialer(marker, addr.Network(), dstIPPort)
		if err != nil {
			scopedLog.WithError(err).WithFields(logrus.Fields{
				"origNetwork": addr.Network(),
				"origDest":    dstIPPort,
			}).Error("Unable to dial original destination")
			return
		}

		pair.Tx.SetConnection(txConn)

		// Start go routine to handle responses and pass in a copy of
		// the request record as template for all responses
		go k.handleResponseConnection(pair, record)
	}

	flowdebug.Log(scopedLog, "Forwarding Kafka request")
	// log valid request
	record.log(accesslog.TypeRequest, accesslog.VerdictForwarded, kafka.ErrNone, "")

	// Write the entire raw request onto the outgoing connection
	pair.Tx.Enqueue(req.GetRaw())
}

type kafkaReqMessageHander func(pair *connectionPair, req *kafka.RequestMessage)
type kafkaRespMessageHander func(pair *connectionPair, req *kafka.ResponseMessage)

func handleRequests(done <-chan struct{}, pair *connectionPair, c *proxyConnection,
	record *kafkaLogRecord, handler kafkaReqMessageHander) {
	defer c.Close()
	scopedLog := log.WithField(fieldID, pair.String())
	for {
		req, err := kafka.ReadRequest(c.conn)

		// Ignore any error if the listen socket has been closed, i.e. the
		// port redirect has been removed.
		select {
		case <-done:
			scopedLog.Debug("Redirect removed; closing Kafka request connection")
			return
		default:
		}

		if err != nil {
			if record != nil {
				record.log(accesslog.TypeRequest, accesslog.VerdictError,
					kafka.ErrInvalidMessage, fmt.Sprintf("Unable to parse Kafka request: %s", err))
			}
			scopedLog.WithError(err).Error("Unable to parse Kafka request; closing Kafka request connection")
			return
		}

		handler(pair, req)
	}
}

func handleResponses(done <-chan struct{}, pair *connectionPair, c *proxyConnection, record kafkaLogRecord, handler kafkaRespMessageHander) {
	defer c.Close()
	scopedLog := log.WithField(fieldID, pair.String())
	for {
		rsp, err := kafka.ReadResponse(c.conn)

		// Ignore any error if the listen socket has been closed, i.e. the
		// port redirect has been removed.
		select {
		case <-done:
			scopedLog.Debug("Redirect removed; closing Kafka response connection")
			return
		default:
		}

		if err != nil {
			record.log(accesslog.TypeResponse, accesslog.VerdictError,
				kafka.ErrInvalidMessage,
				fmt.Sprintf("Unable to parse Kafka response: %s", err))
			scopedLog.WithError(err).Error("Unable to parse Kafka response; closing Kafka response connection")
			return
		}

		record.log(accesslog.TypeResponse, accesslog.VerdictForwarded, kafka.ErrNone, "")

		handler(pair, rsp)
	}
}

func (k *kafkaRedirect) handleRequestConnection(pair *connectionPair) {
	flowdebug.Log(log.WithFields(logrus.Fields{
		"from": pair.Rx,
		"to":   pair.Tx,
	}), "Proxying request Kafka connection")

	handleRequests(k.socket.closing, pair, pair.Rx, nil, k.handleRequest)
}

func (k *kafkaRedirect) handleResponseConnection(pair *connectionPair, record kafkaLogRecord) {
	flowdebug.Log(log.WithFields(logrus.Fields{
		"from": pair.Tx,
		"to":   pair.Rx,
	}), "Proxying response Kafka connection")

	handleResponses(k.socket.closing, pair, pair.Tx, record,
		func(pair *connectionPair, rsp *kafka.ResponseMessage) {
			pair.Rx.Enqueue(rsp.GetRaw())
		})
}

// UpdateRules replaces old l7 rules of a redirect with new ones.
func (k *kafkaRedirect) UpdateRules(l4 *policy.L4Filter, wg *completion.WaitGroup) error {
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
func (k *kafkaRedirect) Close(wg *completion.WaitGroup) {
	k.socket.Close()
}

func init() {
	if err := proto.ConfigureParser(proto.ParserConfig{
		SimplifiedMessageSetParsing: false,
	}); err != nil {
		log.WithError(err).Fatal("Unable to configure kafka parser")
	}
}
