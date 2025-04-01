// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package accesslog

import (
	"bytes"
	"context"
	"encoding/gob"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/dns"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/maps/eventsmap"
	"github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/monitor/agent/listener"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/monitor/payload"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/u8proto"
)

// mockLogRecord is a log entry similar to the one used in fqdn.go for
// DNS related events notification.
func mockLogRecord(accessLogger ProxyAccessLogger) *LogRecord {
	return accessLogger.NewLogRecord(
		TypeResponse,
		false,
		func(lr *LogRecord, _ EndpointInfoRegistry) {
			lr.TransportProtocol = TransportProtocol(
				u8proto.ProtoIDs[strings.ToLower("udp")],
			)
		},
		LogTags.Verdict(
			VerdictForwarded,
			"just a benchmark",
		),
		LogTags.Addressing(context.Background(), AddressingInfo{
			DstIPPort:   "15478",
			DstIdentity: 16,
			SrcIPPort:   "53",
			SrcIdentity: 1,
		}),
		LogTags.DNS(&LogRecordDNS{
			Query: "data.test.svc.cluster.local",
			IPs: []netip.Addr{
				netip.MustParseAddr("1.1.1.1"),
				netip.MustParseAddr("2.2.2.2"),
				netip.MustParseAddr("3.3.3.3"),
			},
			TTL: 43200,
			CNAMEs: []string{
				"alt1.test.svc.cluster.local",
				"alt2.test.svc.cluster.local",
			},
			ObservationSource: DNSSourceProxy,
			RCode:             dns.RcodeSuccess,
			QTypes:            []uint16{dns.TypeA, dns.TypeAAAA},
			AnswerTypes:       []uint16{dns.TypeA, dns.TypeAAAA},
		}),
	)
}

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
	return n.monitorAgent.SendEvent(api.MessageTypeAccessLog, *l)
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

func benchWithoutListeners(b *testing.B, notifier LogRecordNotifier) {
	accessLogger := NewProxyAccessLogger(hivetest.Logger(b), ProxyAccessLoggerConfig{}, notifier, nil)
	node.WithTestLocalNodeStore(func() {
		record := mockLogRecord(accessLogger)
		for _, bm := range benchCases {
			b.Run(bm.name, func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					// Each goroutine will deliver a single notification concurrently.
					// This is done to simulate what happens when a high rate of DNS
					// related events trigger one `notifyOnDNSMsg` callback each and
					// consequently the event logging.
					var wg sync.WaitGroup
					for range bm.nRecords {
						wg.Add(1)
						go func() {
							defer wg.Done()
							accessLogger.Log(record)
						}()
					}
					wg.Wait()
				}
			})
		}
	})
}

func benchWithListeners(accessLogger ProxyAccessLogger, listener *MockMonitorListener, b *testing.B) {
	node.WithTestLocalNodeStore(func() {
		record := mockLogRecord(accessLogger)
		for _, bm := range benchCases {
			b.Run(bm.name, func(b *testing.B) {
				ctx, cancel := context.WithCancel(context.Background())

				var wg sync.WaitGroup
				wg.Add(1)
				listener.Drain(ctx, &wg)

				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					// Each goroutine will deliver a single notification concurrently.
					// This is done to simulate what happens when a high rate of DNS
					// related events trigger one `notifyOnDNSMsg` callback each and
					// consequently the event logging.
					var logWg sync.WaitGroup
					for range bm.nRecords {
						logWg.Add(1)
						go func() {
							defer logWg.Done()
							accessLogger.Log(record)
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
	})
}

func BenchmarkLogNotifierWithNoListeners(b *testing.B) {
	bench := cell.Invoke(func(lc cell.Lifecycle, monitor agent.Agent) error {
		notifier := NewMockLogNotifier(monitor)

		lc.Append(cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				benchWithoutListeners(b, notifier)
				return nil
			},
			OnStop: func(ctx cell.HookContext) error { return nil },
		})

		return nil
	})

	h := hive.New(
		cell.Provide(func() eventsmap.Map { return nil }),
		agent.Cell,
		bench,
	)

	tlog := hivetest.Logger(b)
	if err := h.Start(tlog, context.TODO()); err != nil {
		b.Fatalf("failed to start hive: %v", err)
	}
	if err := h.Stop(tlog, context.TODO()); err != nil {
		b.Fatalf("failed to stop hive: %v", err)
	}
}

func BenchmarkLogNotifierWithListeners(b *testing.B) {
	bench := cell.Invoke(func(lc cell.Lifecycle, monitor agent.Agent, cfg agent.AgentConfig, em eventsmap.Map) error {
		listener := NewMockMonitorListener(cfg.MonitorQueueSize)
		notifier := NewMockLogNotifier(monitor)
		notifier.RegisterNewListener(listener)
		accessLogger := NewProxyAccessLogger(hivetest.Logger(b), ProxyAccessLoggerConfig{}, notifier, nil)

		lc.Append(cell.Hook{
			OnStart: func(ctx cell.HookContext) error {
				benchWithListeners(accessLogger, listener, b)
				return nil
			},
			OnStop: func(ctx cell.HookContext) error { return nil },
		})

		return nil
	})

	h := hive.New(
		cell.Provide(func() eventsmap.Map { return nil }),
		agent.Cell,
		bench,
	)

	tlog := hivetest.Logger(b)
	if err := h.Start(tlog, context.TODO()); err != nil {
		b.Fatalf("failed to start hive: %v", err)
	}
	if err := h.Stop(tlog, context.TODO()); err != nil {
		b.Fatalf("failed to stop hive: %v", err)
	}
}
