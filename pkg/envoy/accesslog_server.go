// Copyright 2017, 2018 Authors of Cilium
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

package envoy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/flowdebug"
	kafka_api "github.com/cilium/cilium/pkg/policy/api/kafka"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/logger"

	"github.com/cilium/proxy/go/cilium/api"
	"github.com/golang/protobuf/proto"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func getAccessLogPath(stateDir string) string {
	return filepath.Join(stateDir, "access_log.sock")
}

type accessLogServer struct {
	xdsServer            *XDSServer
	endpointInfoRegistry logger.EndpointInfoRegistry
}

// StartAccessLogServer starts the access log server.
func StartAccessLogServer(stateDir string, xdsServer *XDSServer, endpointInfoRegistry logger.EndpointInfoRegistry) {
	accessLogPath := getAccessLogPath(stateDir)

	// Create the access log listener
	os.Remove(accessLogPath) // Remove/Unlink the old unix domain socket, if any.
	accessLogListener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: accessLogPath, Net: "unixpacket"})
	if err != nil {
		log.WithError(err).Fatalf("Envoy: Failed to open access log listen socket at %s", accessLogPath)
	}
	accessLogListener.SetUnlinkOnClose(true)

	// Make the socket accessible by non-root Envoy proxies, e.g. running in
	// sidecar containers.
	if err = os.Chmod(accessLogPath, 0777); err != nil {
		log.WithError(err).Fatalf("Envoy: Failed to change mode of access log listen socket at %s", accessLogPath)
	}

	server := accessLogServer{
		xdsServer:            xdsServer,
		endpointInfoRegistry: endpointInfoRegistry,
	}

	go func() {
		for {
			// Each Envoy listener opens a new connection over the Unix domain socket.
			// Multiple worker threads serving the listener share that same connection
			uc, err := accessLogListener.AcceptUnix()
			if err != nil {
				// These errors are expected when we are closing down
				if strings.Contains(err.Error(), "closed network connection") ||
					strings.Contains(err.Error(), "invalid argument") {
					break
				}
				log.WithError(err).Warn("Envoy: Failed to accept access log connection")
				continue
			}
			log.Info("Envoy: Accepted access log connection")

			// Serve this access log socket in a goroutine, so we can serve multiple
			// connections concurrently.
			go server.accessLogger(uc)
		}
	}()
}

func (s *accessLogServer) accessLogger(conn *net.UnixConn) {
	defer func() {
		log.Info("Envoy: Closing access log connection")
		conn.Close()
	}()

	buf := make([]byte, 4096)
	for {
		n, _, flags, _, err := conn.ReadMsgUnix(buf, nil)
		if err != nil {
			if !isEOF(err) {
				log.WithError(err).Error("Envoy: Error while reading from access log connection")
			}
			break
		}
		if flags&unix.MSG_TRUNC != 0 {
			log.Warning("Envoy: Discarded truncated access log message")
			continue
		}
		pblog := cilium.LogEntry{}
		err = proto.Unmarshal(buf[:n], &pblog)
		if err != nil {
			log.WithError(err).Warning("Envoy: Discarded invalid access log message")
			continue
		}

		flowdebug.Log(log.WithFields(logrus.Fields{}),
			fmt.Sprintf("%s: Access log message: %s", pblog.PolicyName, pblog.String()))

		// Correlate the log entry's network policy name with a local endpoint info source.
		localEndpoint := s.xdsServer.getLocalEndpoint(pblog.PolicyName)
		if localEndpoint == nil {
			log.Warnf("Envoy: Discarded access log message for non-existent network policy %s",
				pblog.PolicyName)
			continue
		}

		logRecord(s.endpointInfoRegistry, localEndpoint, &pblog)
	}
}

func logRecord(endpointInfoRegistry logger.EndpointInfoRegistry, localEndpoint logger.EndpointUpdater, pblog *cilium.LogEntry) {
	var kafkaRecord *accesslog.LogRecordKafka
	var kafkaTopics []string

	var l7tags logger.LogTag
	if http := pblog.GetHttp(); http != nil {
		l7tags = logger.LogTags.HTTP(&accesslog.LogRecordHTTP{
			Method:          http.Method,
			Code:            int(http.Status),
			URL:             ParseURL(http.Scheme, http.Host, http.Path),
			Protocol:        GetProtocol(http.HttpProtocol),
			Headers:         GetNetHttpHeaders(http.Headers),
			MissingHeaders:  GetNetHttpHeaders(http.MissingHeaders),
			RejectedHeaders: GetNetHttpHeaders(http.RejectedHeaders),
		})
	} else if kafka := pblog.GetKafka(); kafka != nil {
		kafkaRecord = &accesslog.LogRecordKafka{
			ErrorCode:     int(kafka.ErrorCode),
			APIVersion:    int16(kafka.ApiVersion),
			APIKey:        kafka_api.ApiKeyToString(int16(kafka.ApiKey)),
			CorrelationID: kafka.CorrelationId,
		}
		if len(kafka.Topics) > 0 {
			kafkaRecord.Topic.Topic = kafka.Topics[0]
			if len(kafka.Topics) > 1 {
				kafkaTopics = kafka.Topics[1:] // Rest of the topics
			}
		}
		l7tags = logger.LogTags.Kafka(kafkaRecord)
	} else if l7 := pblog.GetGenericL7(); l7 != nil {
		l7tags = logger.LogTags.L7(&accesslog.LogRecordL7{
			Proto:  l7.GetProto(),
			Fields: l7.GetFields(),
		})
	} else {
		// Default to the deprecated HTTP log format
		l7tags = logger.LogTags.HTTP(&accesslog.LogRecordHTTP{
			Method:   pblog.Method,
			Code:     int(pblog.Status),
			URL:      ParseURL(pblog.Scheme, pblog.Host, pblog.Path),
			Protocol: GetProtocol(pblog.HttpProtocol),
			Headers:  GetNetHttpHeaders(pblog.Headers),
		})
	}

	r := logger.NewLogRecord(endpointInfoRegistry, localEndpoint, GetFlowType(pblog), pblog.IsIngress,
		logger.LogTags.Timestamp(time.Unix(int64(pblog.Timestamp/1000000000), int64(pblog.Timestamp%1000000000))),
		logger.LogTags.Verdict(GetVerdict(pblog), pblog.CiliumRuleRef),
		logger.LogTags.Addressing(logger.AddressingInfo{
			SrcIPPort:   pblog.SourceAddress,
			DstIPPort:   pblog.DestinationAddress,
			SrcIdentity: pblog.SourceSecurityId,
		}), l7tags)

	r.Log()

	// Each kafka topic needs to be logged separately, log the rest if any
	for i := range kafkaTopics {
		kafkaRecord.Topic.Topic = kafkaTopics[i]
		r.Log()
	}

	// Update stats for the endpoint.
	ingress := r.ObservationPoint == accesslog.Ingress
	request := r.Type == accesslog.TypeRequest
	localEndpoint.UpdateProxyStatistics("TCP", r.DestinationEndpoint.Port, ingress, request, r.Verdict)
}
