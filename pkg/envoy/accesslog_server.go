// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"syscall"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/cilium/proxy/pkg/policy/api/kafka"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/time"
)

type AccessLogServer struct {
	logger             *slog.Logger
	accessLogger       accesslog.ProxyAccessLogger
	socketPath         string
	proxyGID           uint
	localEndpointStore *LocalEndpointStore
	stopCh             chan struct{}
	bufferSize         uint
}

func newAccessLogServer(logger *slog.Logger, accessLogger accesslog.ProxyAccessLogger, envoySocketDir string, proxyGID uint, localEndpointStore *LocalEndpointStore, bufferSize uint) *AccessLogServer {
	return &AccessLogServer{
		logger:             logger,
		accessLogger:       accessLogger,
		socketPath:         getAccessLogSocketPath(envoySocketDir),
		proxyGID:           proxyGID,
		localEndpointStore: localEndpointStore,
		bufferSize:         bufferSize,
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
		s.logger.Info("Envoy: Starting access log server listening",
			logfields.Address, socketListener.Addr(),
		)
		for {
			// Each Envoy listener opens a new connection over the Unix domain socket.
			// Multiple worker threads serving the listener share that same connection
			uc, err := socketListener.AcceptUnix()
			if err != nil {
				// These errors are expected when we are closing down
				if errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EINVAL) {
					break
				}
				s.logger.Warn("Envoy: Failed to accept access log connection",
					logfields.Error, err,
				)
				continue
			}
			s.logger.Info("Envoy: Accepted access log connection")

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

	// Make the socket accessible by owner and group only.
	if err = os.Chmod(s.socketPath, 0660); err != nil {
		return nil, fmt.Errorf("failed to change mode of access log listen socket at %s: %w", s.socketPath, err)
	}
	// Change the group to ProxyGID allowing access from any process from that group.
	if err = os.Chown(s.socketPath, -1, int(s.proxyGID)); err != nil {
		s.logger.Warn("Envoy: Failed to change the group of access log listen socket",
			logfields.Path, s.socketPath,
			logfields.Error, err,
		)
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
		s.logger.Info("Envoy: Closing access log connection")
		_ = conn.Close()
		stopCh <- struct{}{}
	}()

	buf := make([]byte, s.bufferSize)
	for {
		n, _, flags, _, err := conn.ReadMsgUnix(buf, nil)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.logger.Error("Envoy: Error while reading from access log connection",
					logfields.Error, err,
				)
			}
			break
		}
		if flags&unix.MSG_TRUNC != 0 {
			s.logger.Warn("Envoy: Discarded truncated access log message - increase buffer size via --envoy-access-log-buffer-size",
				logfields.BufferSize, s.bufferSize,
			)
			continue
		}
		pblog := cilium.LogEntry{}
		err = proto.Unmarshal(buf[:n], &pblog)
		if err != nil {
			s.logger.Warn("Envoy: Discarded invalid access log message",
				logfields.Error, err,
			)
			continue
		}

		if flowdebug.Enabled() {
			s.logger.Debug("Envoy: Received access log message",
				logfields.PolicyID, pblog.PolicyName,
				logfields.Value, pblog.String(),
			)
		}

		r := s.logRecord(ctx, &pblog)

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
			localEndpoint.UpdateProxyStatistics("envoy", "TCP", port, uint16(pblog.ProxyId), ingress, request, r.Verdict)
		}
	}
}

func (s *AccessLogServer) logRecord(ctx context.Context, pblog *cilium.LogEntry) *accesslog.LogRecord {
	var kafkaRecord *accesslog.LogRecordKafka
	var kafkaTopics []string

	var l7tags accesslog.LogTag = func(lr *accesslog.LogRecord, endpointInfoRegistry accesslog.EndpointInfoRegistry) {}

	if httpLogEntry := pblog.GetHttp(); httpLogEntry != nil {
		l7tags = accesslog.LogTags.HTTP(&accesslog.LogRecordHTTP{
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
		l7tags = accesslog.LogTags.Kafka(kafkaRecord)
	} else if l7LogEntry := pblog.GetGenericL7(); l7LogEntry != nil {
		l7tags = accesslog.LogTags.L7(&accesslog.LogRecordL7{
			Proto:  l7LogEntry.GetProto(),
			Fields: l7LogEntry.GetFields(),
		})
	}

	flowType := GetFlowType(pblog)
	// Response access logs from Envoy inherit the source/destination info from the request log
	// message. Swap source/destination info here for the response logs so that they are
	// correct.
	// TODO (jrajahalme): Consider doing this at our Envoy filters instead?
	var addrInfo accesslog.AddressingInfo
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
	r := s.accessLogger.NewLogRecord(flowType, pblog.IsIngress,
		accesslog.LogTags.Timestamp(time.Unix(int64(pblog.Timestamp/1000000000), int64(pblog.Timestamp%1000000000))),
		accesslog.LogTags.Verdict(GetVerdict(pblog), pblog.CiliumRuleRef),
		accesslog.LogTags.Addressing(ctx, addrInfo),
		l7tags,
	)
	s.accessLogger.Log(r)

	// Each kafka topic needs to be logged separately, log the rest if any
	for i := range kafkaTopics {
		kafkaRecord.Topic.Topic = kafkaTopics[i]
		s.accessLogger.Log(r)
	}

	return r
}
