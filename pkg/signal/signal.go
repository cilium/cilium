// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package signal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"

	"github.com/cilium/ebpf/perf"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/signalmap"
	"github.com/cilium/cilium/pkg/metrics"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "signal")

type SignalType uint32

const (
	// SignalNatFillUp denotes potential congestion on the NAT table
	SignalNatFillUp SignalType = iota
	// SignalCTFillUp denotes potential congestion on the CT table
	SignalCTFillUp
	// SignalAuthRequired denotes a connection dropped due to missing authentication
	SignalAuthRequired
	SignalTypeMax
)

var signalName = [SignalTypeMax]string{
	SignalNatFillUp:    "nat_fill_up",
	SignalCTFillUp:     "ct_fill_up",
	SignalAuthRequired: "auth_required",
}

// SignalHandler parses signal data from the perf message via a reader.
// Signal handler functions are only ever called from a single goroutine.
// A nil reader is passed when the handler is closed.
// Returns low-cardinality representation of the signal data to be used in a metric.
type SignalHandler func(io.Reader) (metricData string, err error)

var (
	ErrFullChannel         = errors.New("full channel")
	ErrNilChannel          = errors.New("nil channel")
	ErrRuntimeRegistration = errors.New("runtime registration not supported")
	ErrNoHandlers          = errors.New("no registered signal handlers")
)

// signalSet is a bit mask of signals that have active handlers.
// Zero when all handlers are muted.
type signalSet uint64

type SignalManager interface {
	// RegisterHandler must be called during initialization of the cells using signals.
	RegisterHandler(handler SignalHandler, signals ...SignalType) error

	MuteSignals(signals ...SignalType) error
	UnmuteSignals(signals ...SignalType) error
}

type signalManager struct {
	signalmap signalmap.Map
	handlers  [SignalTypeMax]SignalHandler
	events    signalmap.PerfReader
	done      chan struct{}

	// mutex is needed to sync mute/unmute with events Pause/Resume
	// Atomic Uint64 is used to allow reading active signal bits without
	// taking the mutex
	mutex         lock.Mutex
	activeSignals atomic.Uint64
}

func newSignalManager(signalMap signalmap.Map) *signalManager {
	return &signalManager{
		signalmap: signalMap,
		done:      make(chan struct{}),
	}
}

func (sm *signalManager) isSignalMuted(signal SignalType) bool {
	signals := signalSet(sm.activeSignals.Load())
	return signals&(signalSet(1)<<signal) == 0
}

func (sm *signalManager) isMuted() bool {
	return sm.activeSignals.Load() == 0
}

func (sm *signalManager) setMuted(signals signalSet) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	old := sm.activeSignals.Load()
	new := old &^ uint64(signals)
	sm.activeSignals.Store(new)

	if old != 0 && new == 0 && sm.events != nil {
		// If all signals are muted, then we can turn off perf
		// RB notifications from kernel side, which is much more efficient as
		// no new message is pushed into the RB.
		sm.events.Pause()
	}
}

func (sm *signalManager) setUnmuted(signals signalSet) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	old := sm.activeSignals.Load()
	new := old | uint64(signals)
	sm.activeSignals.Store(new)

	if old == 0 && new != 0 && sm.events != nil {
		// If any of the signals are unmuted, then we must turn on perf
		// RB notifications from kernel side.
		sm.events.Resume()
	}
}

func signalCollectMetrics(signalType, signalData, signalStatus string) {
	metrics.SignalsHandled.WithLabelValues(signalType, signalData, signalStatus).Inc()
}

func (sm *signalManager) signalReceive(msg *perf.Record) {
	var which SignalType
	reader := bytes.NewReader(msg.RawSample)
	if err := binary.Read(reader, byteorder.Native, &which); err != nil {
		log.WithError(err).Warning("cannot parse signal type from BPF datapath")
		return
	}

	if which >= SignalTypeMax {
		log.WithField(logfields.Signal, which).Warning("invalid signal type")
		return
	}

	name := signalName[which]
	handler := sm.handlers[which]
	if handler == nil {
		signalCollectMetrics(name, "", "unregistered")
		return
	}
	if sm.isSignalMuted(which) {
		signalCollectMetrics(name, "", "muted")
		return
	}

	status := "received"
	metricData, err := handler(reader)
	if err != nil {
		if errors.Is(err, ErrFullChannel) {
			status = "channel overflow"
		} else {
			log.WithError(err).WithField(logfields.Signal, name).Warning("cannot parse signal data from BPF datapath")
			status = "parse error"
		}
	}
	signalCollectMetrics(name, metricData, status)
}

// MuteSignals tells to not send any new events for the given signals.
func (sm *signalManager) MuteSignals(signals ...SignalType) error {
	var set signalSet
	for _, signal := range signals {
		if signal >= SignalTypeMax {
			return fmt.Errorf("signal number not supported: %d", signal)
		}
		set |= signalSet(1) << signal
	}
	sm.setMuted(set)
	return nil
}

// UnmuteSignals tells to allow sending new events to the given signals.
func (sm *signalManager) UnmuteSignals(signals ...SignalType) error {
	var set signalSet
	for _, signal := range signals {
		if signal >= SignalTypeMax {
			return fmt.Errorf("signal number not supported: %d", signal)
		}
		set |= signalSet(1) << signal
	}
	sm.setUnmuted(set)
	return nil
}

// ChannelHandler is a generic function returning a SignalHandler that writes
// data from a reader to the channel.
func ChannelHandler[T fmt.Stringer](ch chan<- T) SignalHandler {
	closed := false
	return func(reader io.Reader) (string, error) {
		if ch == nil {
			return "", ErrNilChannel
		}
		if reader == nil {
			if !closed {
				closed = true
				close(ch)
			}
			return "", io.EOF
		}
		var data T
		if err := binary.Read(reader, byteorder.Native, &data); err != nil {
			return "", err
		}
		select {
		case ch <- data:
		default:
			return "", ErrFullChannel
		}
		return data.String(), nil
	}
}

// RegisterHandler registers a signal handler for the given signals.
func (sm *signalManager) RegisterHandler(handler SignalHandler, signals ...SignalType) error {
	if sm.events != nil {
		return ErrRuntimeRegistration
	}

	for _, signal := range signals {
		if signal >= SignalTypeMax {
			return fmt.Errorf("signal number not supported: %d", signal)
		}
		if sm.handlers[signal] != nil {
			return fmt.Errorf("channel for signal number already registered: %d", signal)
		}
	}

	for _, signal := range signals {
		sm.handlers[signal] = handler
		sm.setUnmuted(signalSet(1) << signal)
	}
	return nil
}

// Start signal listener. Called after all the handlers have registered and signalmap.open() has
// been called by hive.
func (sm *signalManager) start() error {
	var err error

	// Start listening for signals only if there are registered handlers
	if sm.isMuted() {
		return ErrNoHandlers
	}

	sm.events, err = sm.signalmap.NewReader()
	if err != nil {
		return fmt.Errorf("cannot open %s map! Ignoring signals: %w", sm.signalmap.MapName(), err)
	}

	go func() {
		log.Info("Datapath signal listener running")
		for {
			record, err := sm.events.Read()
			if err != nil {
				if errors.Is(err, os.ErrClosed) {
					break
				}
				signalCollectMetrics("", "", "error")
				log.WithError(err).WithFields(logrus.Fields{
					logfields.BPFMapName: signalmap.MapName,
				}).Error("failed to read event")
				continue
			}

			if record.LostSamples > 0 {
				signalCollectMetrics("", "", "lost")
				continue
			}
			sm.signalReceive(&record)
		}
		log.Info("Datapath signal listener exiting")

		// Close registered signal channels
		for i, handler := range sm.handlers {
			if handler != nil {
				handler(nil)         // let the handler close it's channel
				sm.handlers[i] = nil // let handler be GC'd
			}
		}
		close(sm.done)
		log.Info("Datapath signal listener done")
	}()

	return nil
}

// stop closes all signal channels
func (sm *signalManager) stop() error {
	err := sm.events.Close()
	if err == nil {
		<-sm.done
	}
	return err
}
