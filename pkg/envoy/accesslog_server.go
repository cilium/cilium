// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/cilium/proxy/pkg/policy/api/kafka"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/time"
)

type AccessLogServer struct {
	socketPath         string
	localEndpointStore *LocalEndpointStore
	stopCh             chan struct{}
}

func newAccessLogServer(envoySocketDir string, localEndpointStore *LocalEndpointStore) *AccessLogServer {
	return &AccessLogServer{
		socketPath:         getAccessLogSocketPath(envoySocketDir),
		localEndpointStore: localEndpointStore,
	}
}

// start starts the access log server.
func (s *AccessLogServer) start() error {
	socketListener, err := s.newSocketListener()
	if err != nil {
		return fmt.Errorf("failed to create socket listener: %w", err)
	}

	s.stopCh = make(chan struct{})

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		log.Infof("Envoy: Starting access log server listening on %s", socketListener.Addr())
		for {
			// Each Envoy listener opens a new connection over the Unix domain socket.
			// Multiple worker threads serving the listener share that same connection
			uc, err := socketListener.AcceptUnix()
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
			go s.handleConn(ctx, uc)
		}
	}()

	go func() {
		<-s.stopCh
		_ = socketListener.Close()
		cancel()
	}()

	return nil
}

func (s *AccessLogServer) newSocketListener() (*net.UnixListener, error) {
	// Remove/Unlink the old unix domain socket, if any.
	_ = os.Remove(s.socketPath)

	// Create the access log listener
	accessLogListener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: s.socketPath, Net: "unixpacket"})
	if err != nil {
		return nil, fmt.Errorf("failed to open access log listen socket at %s: %w", s.socketPath, err)
	}
	accessLogListener.SetUnlinkOnClose(true)

	// Make the socket accessible by owner and group only. Group access is needed for Istio
	// sidecar proxies.
	if err = os.Chmod(s.socketPath, 0660); err != nil {
		return nil, fmt.Errorf("failed to change mode of access log listen socket at %s: %w", s.socketPath, err)
	}
	// Change the group to ProxyGID allowing access from any process from that group.
	if err = os.Chown(s.socketPath, -1, option.Config.ProxyGID); err != nil {
		log.WithError(err).Warningf("Envoy: Failed to change the group of access log listen socket at %s, sidecar proxies may not work", s.socketPath)
	}
	return accessLogListener, nil
}

func (s *AccessLogServer) stop() {
	if s.stopCh != nil {
		s.stopCh <- struct{}{}
	}
}

func (s *AccessLogServer) handleConn(ctx context.Context, conn *net.UnixConn) {
	stopCh := make(chan struct{})

	go func() {
		select {
		case <-stopCh:
		case <-ctx.Done():
			_ = conn.Close()
		}
	}()

	defer func() {
		log.Info("Envoy: Closing access log connection")
		_ = conn.Close()
		stopCh <- struct{}{}
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
		localEndpoint := s.localEndpointStore.getLocalEndpoint(pblog.PolicyName)
		if localEndpoint != nil {
			// Update stats for the endpoint.
			ingress := r.ObservationPoint == accesslog.Ingress
			request := r.Type == accesslog.TypeRequest
			port := r.DestinationEndpoint.Port
			if !request {
				port = r.SourceEndpoint.Port
			}
			localEndpoint.UpdateProxyStatistics("envoy", "TCP", port, ingress, request, r.Verdict)
		}
	}
}

func logRecord(pblog *cilium.LogEntry) *logger.LogRecord {
	var kafkaRecord *accesslog.LogRecordKafka
	var kafkaTopics []string

	var l7tags logger.LogTag = func(lr *logger.LogRecord) {}

	if httpLogEntry := pblog.GetHttp(); httpLogEntry != nil {
		l7tags = logger.LogTags.HTTP(&accesslog.LogRecordHTTP{
			Method:          httpLogEntry.Method,
			Code:            int(httpLogEntry.Status),
			URL:             ParseURL(httpLogEntry.Scheme, httpLogEntry.Host, httpLogEntry.Path),
			Protocol:        GetProtocol(httpLogEntry.HttpProtocol),
			Headers:         GetNetHttpHeaders(httpLogEntry.Headers),
			MissingHeaders:  GetNetHttpHeaders(httpLogEntry.MissingHeaders),
			RejectedHeaders: GetNetHttpHeaders(httpLogEntry.RejectedHeaders),
		})
	} else if kafkaLogEntry := pblog.GetKafka(); kafkaLogEntry != nil {
		kafkaRecord = &accesslog.LogRecordKafka{
			ErrorCode:     int(kafkaLogEntry.ErrorCode),
			APIVersion:    int16(kafkaLogEntry.ApiVersion),
			APIKey:        kafka.ApiKeyToString(int16(kafkaLogEntry.ApiKey)),
			CorrelationID: kafkaLogEntry.CorrelationId,
		}
		if len(kafkaLogEntry.Topics) > 0 {
			kafkaRecord.Topic.Topic = kafkaLogEntry.Topics[0]
			if len(kafkaLogEntry.Topics) > 1 {
				kafkaTopics = kafkaLogEntry.Topics[1:] // Rest of the topics
			}
		}
		l7tags = logger.LogTags.Kafka(kafkaRecord)
	} else if l7LogEntry := pblog.GetGenericL7(); l7LogEntry != nil {
		l7tags = logger.LogTags.L7(&accesslog.LogRecordL7{
			Proto:  l7LogEntry.GetProto(),
			Fields: l7LogEntry.GetFields(),
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
		logger.LogTags.Addressing(addrInfo),
		l7tags,
	)
	r.Log()

	// Each kafka topic needs to be logged separately, log the rest if any
	for i := range kafkaTopics {
		kafkaRecord.Topic.Topic = kafkaTopics[i]
		r.Log()
	}

	return r
}
