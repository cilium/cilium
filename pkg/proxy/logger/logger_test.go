// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logger

import (
	"bytes"
	"context"
	"encoding/gob"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/maps/eventsmap"
	"github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/monitor/agent/listener"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/monitor/payload"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/miekg/dns"
)

// mockLogRecord is a log entry similar to the one used in fqdn.go for
// DNS related events notification.
var mockLogRecord = NewLogRecord(
	accesslog.TypeResponse,
	false,
	func(lr *LogRecord) {
		lr.LogRecord.TransportProtocol = accesslog.TransportProtocol(
			u8proto.ProtoIDs[strings.ToLower("udp")],
		)
	},
	LogTags.Verdict(
		accesslog.VerdictForwarded,
		"just a benchmark",
	),
	LogTags.Addressing(AddressingInfo{
		DstIPPort:   "15478",
		DstIdentity: 16,
		SrcIPPort:   "53",
		SrcIdentity: 1,
	}),
	LogTags.DNS(&accesslog.LogRecordDNS{
		Query: "data.test.svc.cluster.local",
		IPs: []net.IP{
			net.IPv4(1, 1, 1, 1),
			net.IPv4(2, 2, 2, 2),
			net.IPv4(3, 3, 3, 3),
		},
		TTL: 43200,
		CNAMEs: []string{
			"alt1.test.svc.cluster.local",
			"alt2.test.svc.cluster.local",
		},
		ObservationSource: accesslog.DNSSourceProxy,
		RCode:             dns.RcodeSuccess,
		QTypes:            []uint16{dns.TypeA, dns.TypeAAAA},
		AnswerTypes:       []uint16{dns.TypeA, dns.TypeAAAA},
	}),
)

// MockMonitorListener is a mock type used to implement the listener.MonitorListener interface
// for benchmarking purposes.
// Specifically, it mimics the behavior of agent.listenerv1_2
type MockMonitorListener struct {
	queue chan *payload.Payload
}

// NewMockMonitorListener returns a MockMonitorListener ready to be used in the benchmarks below.
func NewMockMonitorListener(queueSize int) *MockMonitorListener {
	return &MockMonitorListener{
		queue: make(chan *payload.Payload, queueSize),
	}
}

// Drain will start the draining of the listener internal queue using a separate goroutine.
func (ml *MockMonitorListener) Drain(ctx context.Context, wg *sync.WaitGroup) {
	go func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			case pl := <-ml.queue:
				var bb bytes.Buffer
				_ = pl.EncodeBinary(gob.NewEncoder(&bb))
			}
		}
	}()
}

// Enqueue sends the payload passed as parameter to the listener internal queue for processing.
func (ml *MockMonitorListener) Enqueue(pl *payload.Payload) {
	select {
	case ml.queue <- pl:
	default:
		// listener queue is full, dropping message
	}
}

// Version returns the API version supported by this listener.
func (ml *MockMonitorListener) Version() listener.Version {
	return listener.Version1_2
}

// Close stops the listener. It is a no-op for MockMonitorListener.
func (ml *MockMonitorListener) Close() {
}

// MockLogNotifier is a mock type used to implement the LogRecordNotifier interface for
// benchmarking purposes.
// Specifically, it mimics the behavior of the Daemon and its implementation of the
// NewProxyLogRecord method.
type MockLogNotifier struct {
	monitorAgent agent.Agent
}

// NewMockLogNotifier returns a MockLogNotifier ready to be used in the benchmarks below.
func NewMockLogNotifier(monitor agent.Agent) *MockLogNotifier {
	return &MockLogNotifier{monitor}
}

// NewProxyLogRecord sends the event to the monitor agent to notify the listeners.
func (n *MockLogNotifier) NewProxyLogRecord(l *LogRecord) error {
	return n.monitorAgent.SendEvent(api.MessageTypeAccessLog, l.LogRecord)
}

// RegisterNewListener adds a listener to the MockLogNotifier.
func (n *MockLogNotifier) RegisterNewListener(l listener.MonitorListener) {
	n.monitorAgent.RegisterNewListener(l)
}

var benchCases = []struct {
	name     string
	nRecords int
}{
	{
		name:     "OneRecord",
		nRecords: 1,
	},
	{
		name:     "TenRecords",
		nRecords: 10,
	},
	{
		name:     "HundredRecords",
		nRecords: 100,
	},
	{
		name:     "ThousandRecords",
		nRecords: 1000,
	},
}

func benchWithoutListeners(b *testing.B) {
	for _, bm := range benchCases {
		b.Run(bm.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				// Each goroutine will deliver a single notification concurrently.
				// This is done to simulate what happens when a high rate of DNS
				// related events trigger one `notifyOnDNSMsg` callback each and
				// consequently the event logging.
				var wg sync.WaitGroup
				for j := 0; j < bm.nRecords; j++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						mockLogRecord.Log()
					}()
				}
				wg.Wait()
			}
		})
	}
}

func benchWithListeners(listener *MockMonitorListener, b *testing.B) {
	for _, bm := range benchCases {
		b.Run(bm.name, func(b *testing.B) {
			ctx, cancel := context.WithCancel(context.Background())

			var wg sync.WaitGroup
			wg.Add(1)
			listener.Drain(ctx, &wg)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Each goroutine will deliver a single notification concurrently.
				// This is done to simulate what happens when a high rate of DNS
				// related events trigger one `notifyOnDNSMsg` callback each and
				// consequently the event logging.
				var logWg sync.WaitGroup
				for j := 0; j < bm.nRecords; j++ {
					logWg.Add(1)
					go func() {
						defer logWg.Done()
						mockLogRecord.Log()
					}()
				}
				logWg.Wait()
			}
			b.StopTimer()

			// wait for listener cleanup
			cancel()
			wg.Wait()
		})
	}
}

func BenchmarkLogNotifierWithNoListeners(b *testing.B) {
	bench := cell.Invoke(func(lc hive.Lifecycle, monitor agent.Agent) error {
		notifier := NewMockLogNotifier(monitor)
		SetNotifier(notifier)

		lc.Append(hive.Hook{
			OnStart: func(ctx hive.HookContext) error {
				benchWithoutListeners(b)
				return nil
			},
			OnStop: func(ctx hive.HookContext) error { return nil },
		})

		return nil
	})

	h := hive.New(
		cell.Provide(func() eventsmap.Map { return nil }),
		agent.Cell,
		bench,
	)

	if err := h.Start(context.TODO()); err != nil {
		b.Fatalf("failed to start hive: %v", err)
	}
	if err := h.Stop(context.TODO()); err != nil {
		b.Fatalf("failed to stop hive: %v", err)
	}
}

func BenchmarkLogNotifierWithListeners(b *testing.B) {
	bench := cell.Invoke(func(lc hive.Lifecycle, monitor agent.Agent, cfg agent.AgentConfig, em eventsmap.Map) error {
		listener := NewMockMonitorListener(cfg.MonitorQueueSize)
		notifier := NewMockLogNotifier(monitor)
		notifier.RegisterNewListener(listener)
		SetNotifier(notifier)

		lc.Append(hive.Hook{
			OnStart: func(ctx hive.HookContext) error {
				benchWithListeners(listener, b)
				return nil
			},
			OnStop: func(ctx hive.HookContext) error { return nil },
		})

		return nil
	})

	h := hive.New(
		cell.Provide(func() eventsmap.Map { return nil }),
		agent.Cell,
		bench,
	)

	if err := h.Start(context.TODO()); err != nil {
		b.Fatalf("failed to start hive: %v", err)
	}
	if err := h.Stop(context.TODO()); err != nil {
		b.Fatalf("failed to stop hive: %v", err)
	}
}
