// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sink

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/hubble/recorder/pcap"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "recorder-sink")

// record is a captured packet which will be written to file in the pcap format
type record struct {
	timestamp time.Time
	ruleID    uint16
	inclLen   uint32
	origLen   uint32
	data      []byte
}

// Handle enables the owner to subscribe to sink statistics
type Handle struct {
	// StatsUpdated is a channel on which receives a new empty message whenever
	// there was an update to the sink statistics.
	StatsUpdated <-chan struct{}
	// Done is a channel which is closed when this sink has been shut down.
	Done <-chan struct{}

	sink *sink
}

// Stats returns the latest statistics for this sink.
func (h *Handle) Stats() Statistics {
	return h.sink.copyStats()
}

// Stop requests the underlying sink to stop. Handle.Done will be closed
// once the sink has drained its queue and stopped.
func (h *Handle) Stop() {
	h.sink.stop()
}

// Err returns the last error on this sink once the channel has stopped
func (h *Handle) Err() error {
	return h.sink.err()
}

// Statistics contains the statistics for a pcap sink
type Statistics struct {
	PacketsWritten uint64
	BytesWritten   uint64
	PacketsLost    uint64
	BytesLost      uint64
}

// StopConditions defines a set of values which cause the sink to stop
// recording if any of them are hit. Zero-valued conditions are ignored.
type StopConditions struct {
	PacketsCaptured uint64
	BytesCaptured   uint64
	DurationElapsed time.Duration
}

// PcapSink defines the parameters of a sink which writes to a pcap.RecordWriter
type PcapSink struct {
	RuleID        uint16
	Header        pcap.Header
	Writer        pcap.RecordWriter
	StopCondition StopConditions
}

// Dispatch implements consumer.MonitorConsumer and dispatches incoming
// recorder captures to registered sinks based on their rule ID.
type Dispatch struct {
	mutex lock.RWMutex

	bootTimeOffset int64

	sinkQueueSize int
	sinkByRuleID  map[uint16]*sink
}

// NewDispatch creates a new sink dispatcher. Each registered sink may have a
// queue of up to sinkQueueSize pending captures.
func NewDispatch(sinkQueueSize int) (*Dispatch, error) {
	if sinkQueueSize < 1 {
		return nil, fmt.Errorf("invalid sink queue size: %d", sinkQueueSize)
	}

	bootTimeOffset, err := estimateBootTimeOffset()
	if err != nil {
		return nil, fmt.Errorf("failed to obtain boot time clock: %w", err)
	}

	return &Dispatch{
		bootTimeOffset: bootTimeOffset,
		sinkQueueSize:  sinkQueueSize,
		sinkByRuleID:   map[uint16]*sink{},
	}, nil
}

// StartSink starts a new sink for the pcap sink configuration p. Any
// captures with a matching rule ID will be forwarded to the pcap sink p.Writer.
// The provided p.Header is written to the pcap sink during initialization.
// The sink is unregistered automatically when it stops. A sink is stopped for
// one of the following four reasons. In all cases, Handle.Done will be closed.
//   - Explicitly via Handle.Stop (Handle.Err() == nil)
//   - When one of the p.StopCondition is hit (Handle.Err() == nil)
//   - When the context ctx is cancelled (Handle.Err() != nil)
//   - When an error occurred (Handle.Err() != nil)
func (d *Dispatch) StartSink(ctx context.Context, p PcapSink) (*Handle, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if _, ok := d.sinkByRuleID[p.RuleID]; ok {
		return nil, fmt.Errorf("sink for rule id %d already registered", p.RuleID)
	}

	s := startSink(ctx, p, d.sinkQueueSize)
	d.sinkByRuleID[p.RuleID] = s

	go func() {
		<-s.done
		d.mutex.Lock()
		delete(d.sinkByRuleID, p.RuleID)
		d.mutex.Unlock()
	}()

	return &Handle{
		StatsUpdated: s.trigger,
		Done:         s.done,
		sink:         s,
	}, nil
}

func (d *Dispatch) decodeRecordCaptureLocked(data []byte) (rec record, err error) {
	dataLen := uint32(len(data))
	if dataLen < monitor.RecorderCaptureLen {
		return record{}, fmt.Errorf("not enough data to decode capture message: %d", dataLen)
	}

	// This needs to stay in sync with struct capture_msg from
	// bpf/include/pcap.h.
	// We could use binary.Read on monitor.RecorderCapture, but since it
	// requires reflection, it is too slow to use on the critical path here.
	const (
		offsetRuleID         = 2
		offsetTimeBoot       = 8
		offsetCaptureLength  = 16
		offsetOriginalLength = 20
	)
	n := byteorder.Native
	ruleID := n.Uint16(data[offsetRuleID:])
	timeBoot := n.Uint64(data[offsetTimeBoot:])
	capLen := n.Uint32(data[offsetCaptureLength:])
	origLen := n.Uint32(data[offsetOriginalLength:])

	// data may contain trailing garbage from the perf ring buffer
	// https://lore.kernel.org/patchwork/patch/1244339/
	packetEnd := monitor.RecorderCaptureLen + capLen
	if dataLen < packetEnd {
		return record{}, fmt.Errorf("capture record too short: want:%d < got:%d", dataLen, packetEnd)
	}
	packet := data[monitor.RecorderCaptureLen:packetEnd]

	return record{
		timestamp: time.Unix(0, d.bootTimeOffset+int64(timeBoot)),
		ruleID:    ruleID,
		inclLen:   capLen,
		origLen:   origLen,
		data:      packet,
	}, nil
}

const estimationRounds = 25

func estimateBootTimeOffset() (bootTimeOffset int64, err error) {
	// The datapath is currently using ktime_get_boot_ns for the pcap timestamp,
	// which corresponds to CLOCK_BOOTTIME. To be able to convert the the
	// CLOCK_BOOTTIME to CLOCK_REALTIME (i.e. a unix timestamp).

	// There can be an arbitrary amount of time between the execution of
	// time.Now() and unix.ClockGettime() below, especially under scheduler
	// pressure during program startup. To reduce the error introduced by these
	// delays, we pin the current Go routine to its OS thread and measure the
	// clocks multiple times, taking only the smallest observed difference
	// between the two values (which implies the smallest possible delay
	// between the two snapshots).
	var minDiff int64 = 1<<63 - 1

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for round := 0; round < estimationRounds; round++ {
		var bootTimespec unix.Timespec

		// Ideally we would use __vdso_clock_gettime for both clocks here,
		// to have as little overhead as possible.
		// time.Now() will actually use VDSO on Go 1.9+, but calling
		// unix.ClockGettime to obtain CLOCK_BOOTTIME is a regular system call
		// for now.
		unixTime := time.Now()
		err = unix.ClockGettime(unix.CLOCK_BOOTTIME, &bootTimespec)
		if err != nil {
			return 0, err
		}

		offset := unixTime.UnixNano() - bootTimespec.Nano()
		diff := offset
		if diff < 0 {
			diff = -diff
		}

		if diff < minDiff {
			minDiff = diff
			bootTimeOffset = offset
		}
	}

	return bootTimeOffset, nil
}

// NotifyPerfEvent implements consumer.MonitorConsumer
func (d *Dispatch) NotifyPerfEvent(data []byte, cpu int) {
	if len(data) == 0 || data[0] != monitorAPI.MessageTypeRecCapture {
		return
	}

	d.mutex.Lock()
	defer d.mutex.Unlock()

	rec, err := d.decodeRecordCaptureLocked(data)
	if err != nil {
		log.WithError(err).Warning("Failed to parse capture record")
		return
	}

	// We silently drop records with unknown rule ids
	if s, ok := d.sinkByRuleID[rec.ruleID]; ok {
		s.enqueue(rec)
	}
}

// NotifyPerfEventLost implements consumer.MonitorConsumer
func (d *Dispatch) NotifyPerfEventLost(numLostEvents uint64, cpu int) {
	log.WithFields(logrus.Fields{
		"numEvents": numLostEvents,
		"cpu":       cpu,
	}).Warning("Perf ring buffer events lost. This may affect captured packets.")
}

// NotifyAgentEvent implements consumer.MonitorConsumer
func (d *Dispatch) NotifyAgentEvent(typ int, message interface{}) {
	// ignored
}
