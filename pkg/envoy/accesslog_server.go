// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/option"
	kafka_api "github.com/cilium/cilium/pkg/policy/api/kafka"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/logger"
)

type accessLogServer struct {
	xdsServer *XDSServer
}

// StartAccessLogServer starts the access log server.
func StartAccessLogServer(envoySocketDir string, xdsServer *XDSServer) {
	accessLogPath := getAccessLogSocketPath(envoySocketDir)

	// Create the access log listener
	os.Remove(accessLogPath) // Remove/Unlink the old unix domain socket, if any.
	accessLogListener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: accessLogPath, Net: "unixpacket"})
	if err != nil {
		log.WithError(err).Fatalf("Envoy: Failed to open access log listen socket at %s", accessLogPath)
	}
	accessLogListener.SetUnlinkOnClose(true)

	// Make the socket accessible by owner and group only. Group access is needed for Istio
	// sidecar proxies.
	if err = os.Chmod(accessLogPath, 0660); err != nil {
		log.WithError(err).Fatalf("Envoy: Failed to change mode of access log listen socket at %s", accessLogPath)
	}
	// Change the group to ProxyGID allowing access from any process from that group.
	if err = os.Chown(accessLogPath, -1, option.Config.ProxyGID); err != nil {
		log.WithError(err).Warningf("Envoy: Failed to change the group of access log listen socket at %s, sidecar proxies may not work", accessLogPath)
	}

	server := accessLogServer{
		xdsServer: xdsServer,
	}

	go func() {
		for {
			// Each Envoy listener opens a new connection over the Unix domain socket.
			// Multiple worker threads serving the listener share that same connection
			uc, err := accessLogListener.AcceptUnix()
			if err != nil {
				// These errors are expected when we are closing down
				if errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EINVAL) {
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
			if !errors.Is(err, io.EOF) {
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

		r := logRecord(&pblog)

		// Update proxy stats for the endpoint if it still exists
		localEndpoint := s.xdsServer.getLocalEndpoint(pblog.PolicyName)
		if localEndpoint != nil {
			// Update stats for the endpoint.
			ingress := r.ObservationPoint == accesslog.Ingress
			request := r.Type == accesslog.TypeRequest
			port := r.DestinationEndpoint.Port
			if !request {
				port = r.SourceEndpoint.Port
			}
			localEndpoint.UpdateProxyStatistics("TCP", port, ingress, request, r.Verdict)
		}
	}
}

func logRecord(pblog *cilium.LogEntry) *logger.LogRecord {
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
	}

	flowType := GetFlowType(pblog)
	// Response access logs from Envoy inherit the source/destination info from the request log
	// message. Swap source/destination info here for the response logs so that they are
	// correct.
	// TODO (jrajahalme): Consider doing this at our Envoy filters instead?
	var addrInfo logger.AddressingInfo
	if flowType == accesslog.TypeResponse {
		addrInfo.DstIPPort = pblog.SourceAddress
		addrInfo.DstIdentity = identity.NumericIdentity(pblog.SourceSecurityId)
		addrInfo.SrcIPPort = pblog.DestinationAddress
		addrInfo.SrcIdentity = identity.NumericIdentity(pblog.DestinationSecurityId)
	} else {
		addrInfo.SrcIPPort = pblog.SourceAddress
		addrInfo.SrcIdentity = identity.NumericIdentity(pblog.SourceSecurityId)
		addrInfo.DstIPPort = pblog.DestinationAddress
		addrInfo.DstIdentity = identity.NumericIdentity(pblog.DestinationSecurityId)
	}
	r := logger.NewLogRecord(flowType, pblog.IsIngress,
		logger.LogTags.Timestamp(time.Unix(int64(pblog.Timestamp/1000000000), int64(pblog.Timestamp%1000000000))),
		logger.LogTags.Verdict(GetVerdict(pblog), pblog.CiliumRuleRef),
		logger.LogTags.Addressing(addrInfo), l7tags)
	r.Log()

	// Each kafka topic needs to be logged separately, log the rest if any
	for i := range kafkaTopics {
		kafkaRecord.Topic.Topic = kafkaTopics[i]
		r.Log()
	}

	return r
}
