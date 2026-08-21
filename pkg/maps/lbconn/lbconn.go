// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbconn

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/registry"
)

const (
	CounterMapName = "cilium_lb_lc"
	GCMapName      = "cilium_lb_lc_gc"
	SockMapName    = "cilium_lb_lc_sock"
)

var Cell = cell.Module(
	"least-connection-tracking",
	"Backend connection counters for least-connection load balancing",

	cell.Provide(provide),
)

type Map interface {
	ctmap.PurgeHook
	DeleteService(uint16) error
}

type mapImpl struct {
	log      *slog.Logger
	counters *bpf.Map
	gc       *bpf.Map
	sock     *bpf.Map
	mu       lock.Mutex
}

func provide(
	lc cell.Lifecycle,
	log *slog.Logger,
	cfg loadbalancer.Config,
	reg *registry.MapRegistry,
) (bpf.MaybeMapOut[Map], defines.NodeOut, error) {
	var nodeOut defines.NodeOut
	if !cfg.AlgorithmAnnotation {
		return bpf.NoneMap[Map](), nodeOut, nil
	}
	nodeOut.NodeDefines = map[string]string{
		"ENABLE_LB_LEAST_CONNECTION":  "1",
		"LB_LEAST_CONNECTION_CHOICES": strconv.Itoa(cfg.LBLeastConnectionChoices),
	}

	m := &mapImpl{log: log}
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) (err error) {
			m.counters, err = bpf.NewMapFromRegistry(
				reg,
				CounterMapName,
				&Key{},
				&CounterValue{},
			)
			if err != nil {
				return fmt.Errorf("create least-connection counter map: %w", err)
			}
			m.gc, err = bpf.NewMapFromRegistry(
				reg,
				GCMapName,
				&Key{},
				&GCValue{},
			)
			if err != nil {
				return fmt.Errorf("create least-connection GC map: %w", err)
			}
			m.sock, err = bpf.NewMapFromRegistry(
				reg,
				SockMapName,
				&SockKey{},
				&SockValue{},
			)
			if err != nil {
				return fmt.Errorf("create least-connection socket map: %w", err)
			}
			if err := errors.Join(
				m.counters.OpenOrCreate(),
				m.gc.OpenOrCreate(),
				m.sock.OpenOrCreate(),
			); err != nil {
				return err
			}
			ctmap.LBConn = m
			return nil
		},
		OnStop: func(cell.HookContext) error {
			if ctmap.LBConn == m {
				ctmap.LBConn = nil
			}
			return errors.Join(m.counters.Close(), m.gc.Close(), m.sock.Close())
		},
	})

	return bpf.SomeMap(Map(m)), nodeOut, nil
}

func (m *mapImpl) DeleteService(svcID uint16) error {
	if m.counters == nil || m.gc == nil || m.sock == nil {
		return errors.New("least-connection maps not started")
	}

	networkSvcID := byteorder.HostToNetwork16(svcID)
	counterKeys := map[Key]struct{}{}
	collectCounterKeys := func(target *bpf.Map) error {
		return target.DumpWithCallback(func(key bpf.MapKey, _ bpf.MapValue) {
			k := *key.(*Key)
			if k.SvcID == networkSvcID {
				counterKeys[k] = struct{}{}
			}
		})
	}
	if err := collectCounterKeys(m.counters); err != nil {
		return fmt.Errorf("dump least-connection counter map: %w", err)
	}
	if err := collectCounterKeys(m.gc); err != nil {
		return fmt.Errorf("dump least-connection GC map: %w", err)
	}

	var sockKeys []*SockKey
	if err := m.sock.DumpWithCallback(func(key bpf.MapKey, value bpf.MapValue) {
		if value.(*SockValue).SvcID == networkSvcID {
			keyCopy := *key.(*SockKey)
			sockKeys = append(sockKeys, &keyCopy)
		}
	}); err != nil {
		return fmt.Errorf("dump least-connection socket map: %w", err)
	}

	var errs []error
	appendDeleteError := func(err error) {
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		}
	}
	for key := range counterKeys {
		key := key
		appendDeleteError(m.counters.Delete(&key))
		appendDeleteError(m.gc.Delete(&key))
	}
	for _, key := range sockKeys {
		appendDeleteError(m.sock.Delete(key))
	}
	return errors.Join(errs...)
}

func (m *mapImpl) CountFailed4(svcID uint16, backendID uint32) {
	m.countFailed(svcID, backendID)
}

func (m *mapImpl) CountFailed6(svcID uint16, backendID uint32) {
	m.countFailed(svcID, backendID)
}

func (m *mapImpl) countFailed(svcID uint16, backendID uint32) {
	key := &Key{
		BackendID: backendID,
		SvcID:     svcID,
	}

	if _, err := m.counters.Lookup(key); errors.Is(err, ebpf.ErrKeyNotExist) {
		return
	} else if err != nil {
		m.log.Error("Failed to look up least-connection counter",
			logfields.ServiceID, svcID,
			logfields.BackendID, backendID,
			logfields.Error, err,
		)
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	value := &GCValue{}
	if v, err := m.gc.Lookup(key); err == nil {
		value = v.(*GCValue)
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		m.log.Error("Failed to look up least-connection GC counter",
			logfields.ServiceID, svcID,
			logfields.BackendID, backendID,
			logfields.Error, err,
		)
		return
	}
	value.Closed++
	if err := m.gc.Update(key, value); err != nil {
		m.log.Error("Failed to update least-connection GC counter",
			logfields.ServiceID, svcID,
			logfields.BackendID, backendID,
			logfields.Error, err,
		)
	}
}

type Key struct {
	BackendID uint32 `align:"backend_id"`
	SvcID     uint16 `align:"svc_id"`
	Pad       uint16 `align:"pad"`
}

func (k *Key) New() bpf.MapKey { return &Key{} }

func (k *Key) String() string {
	return fmt.Sprintf("%d/%d", k.SvcID, k.BackendID)
}

type CounterValue struct {
	Opened uint32 `align:"opened"`
	Closed uint32 `align:"closed"`
}

func (v *CounterValue) New() bpf.MapValue { return &CounterValue{} }

func (v *CounterValue) String() string {
	return fmt.Sprintf("+%d -%d", v.Opened, v.Closed)
}

type GCValue struct {
	Closed uint32
}

func (v *GCValue) New() bpf.MapValue { return &GCValue{} }

func (v *GCValue) String() string {
	return fmt.Sprintf("-%d", v.Closed)
}

type SockKey struct {
	Cookie uint64
}

func (k *SockKey) New() bpf.MapKey { return &SockKey{} }

func (k *SockKey) String() string {
	return fmt.Sprintf("%d", k.Cookie)
}

type SockValue struct {
	BackendID uint32 `align:"backend_id"`
	SvcID     uint16 `align:"svc_id"`
	Pad       uint16 `align:"pad"`
}

func (v *SockValue) New() bpf.MapValue { return &SockValue{} }

func (v *SockValue) String() string {
	return fmt.Sprintf("%d/%d", v.SvcID, v.BackendID)
}
