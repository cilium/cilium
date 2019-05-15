// Copyright 2017-2018 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/revert"
	"io"
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/kafka"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/logger"

	"github.com/optiopay/kafka/proto"
	"github.com/sirupsen/logrus"
)

const (
	fieldID = "id"
)

// The maps holding kafkaListeners (and kafkaRedirects), as well as
// the reference `count` field are protected by `mutex`. `socket` is safe
// to be used from multiple goroutines and the other fields below are
// immutable after initialization.
type kafkaListener struct {
	socket               *proxySocket
	proxyPort            uint16
	endpointInfoRegistry logger.EndpointInfoRegistry
	ingress              bool
	transparent          bool
	count                int
}

var (
	mutex          lock.RWMutex                      // mutex protects accesses to the configuration resources.
	kafkaListeners = make(map[uint16]*kafkaListener) // key: proxy port
	kafkaRedirects = make(map[uint64]*kafkaRedirect) // key: dst port | dir << 16 | endpoint ID << 32
)

func mapKey(dstPort uint16, ingress bool, eID uint16) uint64 {
	var dir uint64
	if ingress {
		dir = 1
	}
	return uint64(dstPort) | dir<<16 | uint64(eID)<<32
}

// kafkaRedirect implements the RedirectImplementation interface
// This extends the Redirect with Kafka specific state.
// 'listener' is shared accross multiple kafkaRedirects
// 'redirect' is unique for this kafkaRedirect
type kafkaRedirect struct {
	listener             *kafkaListener
	redirect             *Redirect
	endpointInfoRegistry logger.EndpointInfoRegistry
	conf                 kafkaConfiguration
}

type srcIDLookupFunc func(mapname, remoteAddr, localAddr string, ingress bool) (uint32, error)

type kafkaConfiguration struct {
	testMode    bool
	lookupSrcID srcIDLookupFunc
}

func (l *kafkaListener) Listen() {
	for {
		pair, err := l.socket.Accept(true)
		select {
		case <-l.socket.closing:
			// Don't report errors while the socket is being closed
			return
		default:
		}

		if err != nil {
			log.WithField(logfields.Port, l.proxyPort).WithError(err).Error("Unable to accept connection on port")
			continue
		}
		// Locate the redirect for this connection
		endpointIPStr, dstPortStr, err := net.SplitHostPort(pair.Rx.conn.LocalAddr().String())
		if err != nil {
			log.WithField(logfields.Port, l.proxyPort).WithError(err).Error("No destination address")
			continue
		}
		if !l.ingress {
			// for egress EP is the source
			endpointIPStr, _, err = net.SplitHostPort(pair.Rx.conn.RemoteAddr().String())
			if err != nil {
				log.WithField(logfields.Port, l.proxyPort).WithError(err).Error("No source address")
				continue
			}
		}
		var epinfo accesslog.EndpointInfo
		if !l.endpointInfoRegistry.FillEndpointIdentityByIP(net.ParseIP(endpointIPStr), &epinfo) {
			log.WithField(logfields.Port, l.proxyPort).Errorf("Can't find endpoint with IP %s", endpointIPStr)
			continue
		}
		portInt, _ := strconv.Atoi(dstPortStr)
		key := mapKey(uint16(portInt), l.ingress, uint16(epinfo.ID))
		log.WithField(logfields.EndpointID, epinfo.ID).Debugf("Looking up Kafka redirect with port: %d, ingress: %v", uint16(portInt), l.ingress)

		mutex.Lock()
		redir, ok := kafkaRedirects[key]
		mutex.Unlock()
		if ok && redir != nil {
			go redir.handleRequestConnection(pair)
		} else {
			log.WithField(logfields.Port, l.proxyPort).Error("No redirect found for accepted connection")
		}
	}
}

// createKafkaRedirect creates a redirect to the kafka proxy. The redirect structure passed
// in is safe to access for reading and writing.
func createKafkaRedirect(r *Redirect, conf kafkaConfiguration, endpointInfoRegistry logger.EndpointInfoRegistry) (RedirectImplementation, error) {
	redir := &kafkaRedirect{
		redirect:             r,
		conf:                 conf,
		endpointInfoRegistry: endpointInfoRegistry,
	}

	if redir.conf.lookupSrcID == nil {
		redir.conf.lookupSrcID = lookupSrcID
	}

	// must register with the proxy port for unit tests (no IP_TRANSPARENT)
	dstPort := r.dstPort
	if conf.testMode {
		dstPort = r.listener.proxyPort
	}
	key := mapKey(dstPort, r.listener.ingress, uint16(r.endpointID))
	log.WithField(logfields.EndpointID, r.endpointID).Debugf(
		"Registering %s with port: %d, ingress: %v",
		r.listener.name, dstPort, r.listener.ingress)
	mutex.Lock()
	if _, ok := kafkaRedirects[key]; ok {
		mutex.Unlock()
		panic("Kafka redirect already exists for the given dst port and endpoint ID")
	}
	kafkaRedirects[key] = redir

	// Start a listener if not already running
	listener := kafkaListeners[r.listener.proxyPort]
	if listener == nil {
		marker := 0
		if !conf.testMode {
			marker = linux_defaults.GetMagicProxyMark(r.listener.ingress, 0)
		}

		// Listen needs to be in the synchronous part of this function to ensure that
		// the proxy port is never refusing connections.
		socket, err := listenSocket(fmt.Sprintf(":%d", r.listener.proxyPort), marker, !conf.testMode)
		if err != nil {
			delete(kafkaRedirects, key)
			mutex.Unlock()
			return nil, err
		}
		listener = &kafkaListener{
			socket:               socket,
			proxyPort:            r.listener.proxyPort,
			endpointInfoRegistry: endpointInfoRegistry,
			ingress:              r.listener.ingress,
			transparent:          !conf.testMode,
			count:                0,
		}

		go listener.Listen()

		kafkaListeners[r.listener.proxyPort] = listener
	}
	listener.count++
	redir.listener = listener
	mutex.Unlock()

	return redir, nil
}

// canAccess determines if the kafka message req sent by identity is allowed to
// be forwarded according to the rules configured on kafkaRedirect
func (k *kafkaRedirect) canAccess(req *kafka.RequestMessage, srcIdentity identity.NumericIdentity) bool {
	scopedLog := log.WithFields(logrus.Fields{
		logfields.Request: req.String(),
		"NumericIdentity": srcIdentity,
	})

	k.redirect.mutex.RLock()
	rules := k.redirect.rules.GetRelevantRulesForKafka(srcIdentity)
	k.redirect.mutex.RUnlock()

	if len(rules) == 0 {
		flowdebug.Log(scopedLog, "No Kafka rules matching identity, rejecting")
		return false
	}

	if flowdebug.Enabled() {
		b, err := json.Marshal(rules)
		if err != nil {
			flowdebug.Log(scopedLog, "Error marshalling kafka rules to apply")
			return false
		} else {
			flowdebug.Log(scopedLog.WithField("rule", string(b)), "Applying rule")
		}
	}

	return req.MatchesRule(rules)
}

// kafkaLogRecord wraps an accesslog.LogRecord so that we can define methods with a receiver
type kafkaLogRecord struct {
	*logger.LogRecord
	localEndpoint logger.EndpointUpdater
	topics        []string
}

func apiKeyToString(apiKey int16) string {
	if key, ok := api.KafkaReverseAPIKeyMap[apiKey]; ok {
		return key
	}
	return fmt.Sprintf("%d", apiKey)
}

func (k *kafkaRedirect) newLogRecordFromRequest(req *kafka.RequestMessage) kafkaLogRecord {
	return kafkaLogRecord{
		LogRecord: logger.NewLogRecord(k.endpointInfoRegistry, k.redirect.localEndpoint,
			accesslog.TypeRequest, k.redirect.listener.ingress,
			logger.LogTags.Kafka(&accesslog.LogRecordKafka{
				APIVersion:    req.GetVersion(),
				APIKey:        apiKeyToString(req.GetAPIKey()),
				CorrelationID: int32(req.GetCorrelationID()),
			})),
		localEndpoint: k.redirect.localEndpoint,
		topics:        req.GetTopics(),
	}
}

func (k *kafkaRedirect) newLogRecordFromResponse(res *kafka.ResponseMessage, req *kafka.RequestMessage) kafkaLogRecord {
	lr := kafkaLogRecord{
		LogRecord: logger.NewLogRecord(k.endpointInfoRegistry, k.redirect.localEndpoint,
			accesslog.TypeResponse, k.redirect.listener.ingress, logger.LogTags.Kafka(&accesslog.LogRecordKafka{})),
		localEndpoint: k.redirect.localEndpoint,
	}

	if res != nil {
		lr.Kafka.CorrelationID = int32(res.GetCorrelationID())
	}

	if req != nil {
		lr.Kafka.APIVersion = req.GetVersion()
		lr.Kafka.APIKey = apiKeyToString(req.GetAPIKey())
		lr.topics = req.GetTopics()
	}

	return lr
}

// log Kafka log records
func (l *kafkaLogRecord) log(verdict accesslog.FlowVerdict, code int, info string) {
	l.ApplyTags(logger.LogTags.Verdict(verdict, info))
	l.Kafka.ErrorCode = code

	// Log multiple entries for multiple Kafka topics in a single request.
	for _, t := range l.topics {
		l.Kafka.Topic.Topic = t
		l.Log()
	}

	// Update stats for the endpoint.
	// Count only one request.
	ingress := l.ObservationPoint == accesslog.Ingress
	var port uint16
	if ingress {
		port = l.DestinationEndpoint.Port
	} else {
		port = l.SourceEndpoint.Port
	}
	if port == 0 {
		// Something went wrong when identifying the endpoints.
		// Ignore in order to avoid polluting the stats.
		return
	}
	request := l.Type == accesslog.TypeRequest
	l.localEndpoint.UpdateProxyStatistics("kafka", port, ingress, request, l.Verdict)

}

func (k *kafkaRedirect) handleRequest(pair *connectionPair, req *kafka.RequestMessage, correlationCache *kafka.CorrelationCache,
	remoteAddr net.Addr, remoteIdentity uint32, origDstAddr string) {
	scopedLog := log.WithField(fieldID, pair.String())
	flowdebug.Log(scopedLog.WithField(logfields.Request, req.String()), "Handling Kafka request")

	record := k.newLogRecordFromRequest(req)

	record.ApplyTags(logger.LogTags.Addressing(logger.AddressingInfo{
		SrcIPPort:   remoteAddr.String(),
		DstIPPort:   origDstAddr,
		SrcIdentity: remoteIdentity,
	}))

	if !k.canAccess(req, identity.NumericIdentity(remoteIdentity)) {
		flowdebug.Log(scopedLog, "Kafka request is denied by policy")

		resp, err := req.CreateResponse(proto.ErrTopicAuthorizationFailed)
		if err != nil {
			record.log(accesslog.VerdictError,
				kafka.ErrInvalidMessage, fmt.Sprintf("Unable to create response: %s", err))
			scopedLog.WithError(err).Error("Unable to create Kafka response")
			return
		}

		record.log(accesslog.VerdictDenied,
			kafka.ErrTopicAuthorizationFailed, fmt.Sprint("Kafka request is denied by policy"))

		pair.Rx.Enqueue(resp.GetRaw())
		return
	}

	if pair.Tx.Closed() {
		marker := 0
		if !k.conf.testMode {
			marker = linux_defaults.GetMagicProxyMark(k.redirect.listener.ingress, int(remoteIdentity))
		}

		flowdebug.Log(scopedLog.WithFields(logrus.Fields{
			"marker":      marker,
			"destination": origDstAddr,
		}), "Dialing original destination")

		txConn, err := ciliumDialer(marker, remoteAddr.Network(), origDstAddr)
		if err != nil {
			scopedLog.WithError(err).WithFields(logrus.Fields{
				"origNetwork": remoteAddr.Network(),
				"origDest":    origDstAddr,
			}).Error("Unable to dial original destination")

			record.log(accesslog.VerdictError,
				kafka.ErrNetwork, fmt.Sprintf("Unable to dial original destination: %s", err))

			return
		}

		pair.Tx.SetConnection(txConn)

		// Start go routine to handle responses and pass in a copy of
		// the request record as template for all responses
		go k.handleResponseConnection(pair, correlationCache, remoteAddr, remoteIdentity, origDstAddr)
	}

	// The request is allowed so we will forward it:
	// 1. Rewrite the correlation ID to a unique ID, it will be restored in
	//    the response direction
	// 2. Store the request in the correlation cache
	correlationCache.HandleRequest(req, nil)

	flowdebug.Log(scopedLog, "Forwarding Kafka request")
	// log valid request
	record.log(accesslog.VerdictForwarded, kafka.ErrNone, "")

	// Write the entire raw request onto the outgoing connection
	pair.Tx.Enqueue(req.GetRaw())
}

type kafkaReqMessageHander func(pair *connectionPair, req *kafka.RequestMessage, correlationCache *kafka.CorrelationCache,
	remoteAddr net.Addr, remoteIdentity uint32, origDstAddr string)
type kafkaRespMessageHander func(pair *connectionPair, req *kafka.ResponseMessage)

func (k *kafkaRedirect) handleRequests(done <-chan struct{}, pair *connectionPair, c *proxyConnection,
	handler kafkaReqMessageHander) {
	defer c.Close()

	scopedLog := log.WithField(fieldID, pair.String())

	remoteAddr := pair.Rx.conn.RemoteAddr()
	if remoteAddr == nil {
		scopedLog.Error("Kafka request connection has no remote address")
		return
	}

	localAddr := pair.Rx.conn.LocalAddr()
	if localAddr == nil {
		scopedLog.Error("Kafka request connection has no local address")
		return
	}

	// retrieve identity of source
	k.redirect.localEndpoint.UnconditionalRLock()
	mapname := k.redirect.localEndpoint.ConntrackName()
	k.redirect.localEndpoint.RUnlock()
	srcIdentity, err := k.conf.lookupSrcID(mapname, remoteAddr.String(), localAddr.String(), k.redirect.listener.ingress)
	if err != nil {
		scopedLog.WithField("source",
			remoteAddr.String()).WithError(err).Error("Unable to lookup source security ID")
		return
	}

	// create a correlation cache
	correlationCache := kafka.NewCorrelationCache()
	defer correlationCache.DeleteCache()

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
			if err != io.ErrUnexpectedEOF && err != io.EOF {
				scopedLog.WithError(err).Error("Unable to parse Kafka request; closing Kafka request connection")
			}
			return
		}
		origDstAddr := localAddr.String()
		if k.conf.testMode {
			origDstAddr = fmt.Sprintf("127.0.0.1:%d", k.redirect.dstPort)
		}
		scopedLog.Debugf("Forwarding request to %s", origDstAddr)
		handler(pair, req, correlationCache, remoteAddr, srcIdentity, origDstAddr)
	}
}

func (k *kafkaRedirect) handleResponses(done <-chan struct{}, pair *connectionPair, c *proxyConnection,
	correlationCache *kafka.CorrelationCache, handler kafkaRespMessageHander,
	remoteAddr net.Addr, remoteIdentity uint32, origDstAddr string) {
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
			record := k.newLogRecordFromResponse(nil, nil)
			record.log(accesslog.VerdictError,
				kafka.ErrInvalidMessage,
				fmt.Sprintf("Unable to parse Kafka response: %s", err))
			scopedLog.WithError(err).Error("Unable to parse Kafka response; closing Kafka response connection")
			return
		}

		// 1. Find the request that correlates with this response based
		//    on the correlation ID
		// 2. Restore the original correlation id that was overwritten
		//    by the proxy so the client is guaranteed to see the
		//    correlation id as expected
		req := correlationCache.CorrelateResponse(rsp)

		record := k.newLogRecordFromResponse(rsp, req)
		record.ApplyTags(logger.LogTags.Addressing(logger.AddressingInfo{
			SrcIPPort:   remoteAddr.String(),
			DstIPPort:   origDstAddr,
			SrcIdentity: remoteIdentity,
		}))
		record.log(accesslog.VerdictForwarded, kafka.ErrNone, "")

		handler(pair, rsp)
	}
}

func (k *kafkaRedirect) handleRequestConnection(pair *connectionPair) {
	flowdebug.Log(log.WithFields(logrus.Fields{
		"from": pair.Rx,
		"to":   pair.Tx,
	}), "Proxying request Kafka connection")

	k.handleRequests(k.listener.socket.closing, pair, pair.Rx, k.handleRequest)
}

func (k *kafkaRedirect) handleResponseConnection(pair *connectionPair, correlationCache *kafka.CorrelationCache,
	remoteAddr net.Addr, remoteIdentity uint32, origDstAddr string) {
	flowdebug.Log(log.WithFields(logrus.Fields{
		"from": pair.Tx,
		"to":   pair.Rx,
	}), "Proxying response Kafka connection")

	k.handleResponses(k.listener.socket.closing, pair, pair.Tx, correlationCache,
		func(pair *connectionPair, rsp *kafka.ResponseMessage) {
			pair.Rx.Enqueue(rsp.GetRaw())
		}, remoteAddr, remoteIdentity, origDstAddr)
}

// UpdateRules is a no-op for kafka redirects, as rules are read directly
// during request processing.
func (k *kafkaRedirect) UpdateRules(wg *completion.WaitGroup, l4 *policy.L4Filter) (revert.RevertFunc, error) {
	return func() error { return nil }, nil
}

// Close the redirect.
func (k *kafkaRedirect) Close(wg *completion.WaitGroup) (revert.FinalizeFunc, revert.RevertFunc) {
	return func() {
		r := k.redirect
		log.WithField(logfields.EndpointID, r.endpointID).Debugf("Un-Registering %s port: %d",
			r.listener.name, r.dstPort)
		key := mapKey(r.dstPort, r.listener.ingress, uint16(r.endpointID))

		mutex.Lock()
		delete(kafkaRedirects, key)
		k.listener.count--
		log.Debugf("Close: Listener count: %d", k.listener.count)
		if k.listener.count == 0 {
			k.listener.socket.Close()
			delete(kafkaListeners, r.listener.proxyPort)
		}
		mutex.Unlock()
	}, nil
}

func init() {
	if err := proto.ConfigureParser(proto.ParserConfig{
		SimplifiedMessageSetParsing: false,
	}); err != nil {
		log.WithError(err).Fatal("Unable to configure kafka parser")
	}
}
