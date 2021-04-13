// Copyright 2021 Authors of Cilium
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

package sink

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/hubble/recorder/pcap"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
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
	// C is a channel on which receives a new empty message whenever there
	// was an update to the sink statistics. It is closed when the sink stops
	// updating.
	C    <-chan struct{}
	sink *sink
}

// Statistics contains the statistics for a pcap sink
type Statistics struct {
	PacketsWritten uint64
	BytesWritten   uint64
	PacketsLost    uint64
	BytesLost      uint64
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

// RegisterSink registers a new sink for the given rule ID. Any captures with a
// matching rule ID will be forwarded to the pcap sink w. The provided header
// is written to the pcap sink w upon initialization.
func (d *Dispatch) RegisterSink(ctx context.Context, ruleID uint16, w pcap.RecordWriter, header pcap.Header) (*Handle, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()

	if _, ok := d.sinkByRuleID[ruleID]; ok {
		return nil, fmt.Errorf("sink for rule id %d already registered", ruleID)
	}

	s := startSink(ctx, w, header, d.sinkQueueSize)
	d.sinkByRuleID[ruleID] = s
	return &Handle{
		C:    s.trigger,
		sink: s,
	}, nil
}

// UnregisterSink will stop and unregister the sink for the given ruleID.
// It waits for any pending packets to be forwarded to the sink before closing
// it and returns the final statistics or an error, if an error occurred.
func (d *Dispatch) UnregisterSink(ctx context.Context, ruleID uint16) (stats Statistics, err error) {
	d.mutex.Lock()
	s, ok := d.sinkByRuleID[ruleID]
	delete(d.sinkByRuleID, ruleID)
	// unlock early to avoid holding the lock during s.close() which may block
	d.mutex.Unlock()

	if !ok {
		return Statistics{}, fmt.Errorf("no sink found for rule id %d", ruleID)
	}

	if err = s.close(ctx); err != nil {
		return Statistics{}, err
	}

	return s.copyStats(), nil
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

func (h *Handle) Stats() Statistics {
	return h.sink.copyStats()
}
