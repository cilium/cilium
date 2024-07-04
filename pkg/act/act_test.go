// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package act

import (
	"context"
	"fmt"
	"math"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/maps/act"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

func TestCell(t *testing.T) {
	err := hive.New(act.Cell, Cell).Populate(hivetest.Logger(t))
	if err != nil {
		t.Fatal(err)
	}
}

type mapMock struct {
	deletedKeys []act.ActiveConnectionTrackerKey
}

func (*mapMock) IterateWithCallback(context.Context, act.ActiveConnectionTrackingIterateCallback) error {
	return nil
}

func (m *mapMock) Delete(key *act.ActiveConnectionTrackerKey) error {
	m.deletedKeys = append(m.deletedKeys, *key)
	return nil
}

func TestCallback(t *testing.T) {
	opts := &option.DaemonConfig{
		FixedZoneMapping: map[string]uint8{
			"zone-a": 123,
			"zone-b": 234,
		},
		ReverseFixedZoneMapping: map[uint8]string{
			123: "zone-a",
			234: "zone-b",
		},
	}
	a := newAct(hivetest.Logger(t), new(mapMock), NewActiveConnectionTrackingMetrics(), opts)

	// Initialize
	a.keyToStrings = func(key *act.ActiveConnectionTrackerKey) (zone string, svc string, err error) {
		return "zone-a", "svc-a", nil
	}
	key := &act.ActiveConnectionTrackerKey{SvcID: 1, Zone: 123}
	value := &act.ActiveConnectionTrackerValue{Opened: 2, Closed: 1}
	a.callback(key, value)
	require.Equal(t, 0.0, a.metrics.Active.WithLabelValues("zone-a", "svc-a").Get())
	require.Equal(t, 0.0, a.metrics.New.WithLabelValues("zone-a", "svc-a").Get())
	require.Equal(t, 0.0, a.metrics.Failed.WithLabelValues("zone-a", "svc-a").Get())

	// Update
	key = &act.ActiveConnectionTrackerKey{SvcID: 1, Zone: 123}
	value = &act.ActiveConnectionTrackerValue{Opened: 3, Closed: 1}
	a.callback(key, value)
	require.Equal(t, 2.0, a.metrics.Active.WithLabelValues("zone-a", "svc-a").Get())
	require.Equal(t, 1.0, a.metrics.New.WithLabelValues("zone-a", "svc-a").Get())
	require.Equal(t, 0.0, a.metrics.Failed.WithLabelValues("zone-a", "svc-a").Get())

	// Roll-over
	a.keyToStrings = func(key *act.ActiveConnectionTrackerKey) (zone string, svc string, err error) {
		return "zone-a", "svc-b", nil
	}
	key = &act.ActiveConnectionTrackerKey{SvcID: 2, Zone: 123}
	value = &act.ActiveConnectionTrackerValue{Opened: math.MaxInt32, Closed: math.MaxInt32}
	a.callback(key, value)
	value = &act.ActiveConnectionTrackerValue{Opened: 1, Closed: 1}
	a.callback(key, value)
	require.Equal(t, 0.0, a.metrics.Active.WithLabelValues("zone-a", "svc-b").Get())
	require.Equal(t, math.MaxInt32+2.0, a.metrics.New.WithLabelValues("zone-a", "svc-b").Get())
	require.Equal(t, 0.0, a.metrics.Failed.WithLabelValues("zone-a", "svc-b").Get())

	t.Run("invalid_zone", func(t *testing.T) {
		// Ignore invalid zones
		a.keyToStrings = func(key *act.ActiveConnectionTrackerKey) (zone string, svc string, err error) {
			return "", "", fmt.Errorf("invalid zone")
		}
		key = &act.ActiveConnectionTrackerKey{SvcID: 1, Zone: 101}
		value = &act.ActiveConnectionTrackerValue{Opened: 101, Closed: 98}
		a.callback(key, value)
		a.callback(key, value)
		require.Empty(t, a.metrics.Active.WithLabelValues("", "svc-a").Get())
		require.Empty(t, a.metrics.New.WithLabelValues("", "svc-a").Get())
		require.Empty(t, a.metrics.Failed.WithLabelValues("", "svc-a").Get())
		require.Equal(t, 2.0, a.metrics.Active.WithLabelValues("zone-a", "svc-a").Get())
		require.Equal(t, 1.0, a.metrics.New.WithLabelValues("zone-a", "svc-a").Get())
		require.Equal(t, 0.0, a.metrics.Failed.WithLabelValues("zone-a", "svc-a").Get())
	})

	t.Run("count_failed", func(t *testing.T) {
		// Mark failure
		a.keyToStrings = func(key *act.ActiveConnectionTrackerKey) (zone string, svc string, err error) {
			return "zone-b", "svc-b", nil
		}
		key = &act.ActiveConnectionTrackerKey{SvcID: 2, Zone: 234}
		value = &act.ActiveConnectionTrackerValue{Opened: 101, Closed: 101}
		a.callback(key, value)
		a.tracker[234][2].newFailed++
		value = &act.ActiveConnectionTrackerValue{Opened: 151, Closed: 140}
		a.callback(key, value)
		require.Equal(t, 10.0, a.metrics.Active.WithLabelValues("zone-b", "svc-b").Get())
		require.Equal(t, 50.0, a.metrics.New.WithLabelValues("zone-b", "svc-b").Get())
		require.Equal(t, 1.0, a.metrics.Failed.WithLabelValues("zone-b", "svc-b").Get())
		require.EqualValues(t, 0, a.tracker[234][2].newFailed)
		require.EqualValues(t, 1, a.tracker[234][2].failed)

		// Count failure only once
		value = &act.ActiveConnectionTrackerValue{Opened: 161, Closed: 150}
		a.callback(key, value)
		require.Equal(t, 10.0, a.metrics.Active.WithLabelValues("zone-b", "svc-b").Get())
		require.Equal(t, 10.0, a.metrics.New.WithLabelValues("zone-b", "svc-b").Get())
		require.Equal(t, 0.0, a.metrics.Failed.WithLabelValues("zone-b", "svc-b").Get())
		require.EqualValues(t, 0, a.tracker[234][2].newFailed)
		require.EqualValues(t, 1, a.tracker[234][2].failed)
	})
}

func TestCleanup(t *testing.T) {
	opts := &option.DaemonConfig{
		FixedZoneMapping: map[string]uint8{
			"zone-a": 123,
			"zone-b": 234,
		},
		ReverseFixedZoneMapping: map[uint8]string{
			123: "zone-a",
			234: "zone-b",
		},
	}
	m := new(mapMock)
	a := newAct(hivetest.Logger(t), m, NewActiveConnectionTrackingMetrics(), opts)

	// Initialize entry with updates
	a.keyToStrings = func(key *act.ActiveConnectionTrackerKey) (zone string, svc string, err error) {
		return "zone-a", "svc-a", nil
	}
	key := &act.ActiveConnectionTrackerKey{SvcID: 1, Zone: 123}
	value := &act.ActiveConnectionTrackerValue{Opened: 2, Closed: 1}
	a.callback(key, value)
	value = &act.ActiveConnectionTrackerValue{Opened: 4, Closed: 1}
	a.tracker[123][1].newFailed++
	a.callback(key, value)
	require.Equal(t, 2.0, a.metrics.Active.WithLabelValues("zone-a", "svc-a").Get())
	require.Equal(t, 2.0, a.metrics.New.WithLabelValues("zone-a", "svc-a").Get())
	require.Equal(t, 1.0, a.metrics.Failed.WithLabelValues("zone-a", "svc-a").Get())

	// Initialize entry without updates
	a.keyToStrings = func(key *act.ActiveConnectionTrackerKey) (zone string, svc string, err error) {
		return "zone-a", "svc-b", nil
	}
	key = &act.ActiveConnectionTrackerKey{SvcID: 2, Zone: 123}
	value = &act.ActiveConnectionTrackerValue{Opened: 10, Closed: 5}
	a.callback(key, value)
	require.Equal(t, 0.0, a.metrics.Active.WithLabelValues("zone-a", "svc-b").Get())
	require.Equal(t, 0.0, a.metrics.New.WithLabelValues("zone-a", "svc-b").Get())
	require.Equal(t, 0.0, a.metrics.Failed.WithLabelValues("zone-a", "svc-b").Get())

	// Initialize entry created before cutoff but with updates later
	a.keyToStrings = func(key *act.ActiveConnectionTrackerKey) (zone string, svc string, err error) {
		return "zone-b", "svc-b", nil
	}
	key = &act.ActiveConnectionTrackerKey{SvcID: 2, Zone: 234}
	value = &act.ActiveConnectionTrackerValue{Opened: 1, Closed: 1}
	a.callback(key, value)

	cutoff := time.Now()

	// Initialize entry without updates after cutoff
	a.keyToStrings = func(key *act.ActiveConnectionTrackerKey) (zone string, svc string, err error) {
		return "zone-b", "svc-a", nil
	}
	key = &act.ActiveConnectionTrackerKey{SvcID: 1, Zone: 234}
	value = &act.ActiveConnectionTrackerValue{Opened: 100, Closed: 50}
	a.callback(key, value)
	require.Equal(t, 0.0, a.metrics.Active.WithLabelValues("zone-b", "svc-a").Get())
	require.Equal(t, 0.0, a.metrics.New.WithLabelValues("zone-b", "svc-a").Get())
	require.Equal(t, 0.0, a.metrics.Failed.WithLabelValues("zone-b", "svc-a").Get())

	// later updates
	key = &act.ActiveConnectionTrackerKey{SvcID: 2, Zone: 234}
	value = &act.ActiveConnectionTrackerValue{Opened: 3, Closed: 2}
	a.callback(key, value)
	require.Equal(t, 1.0, a.metrics.Active.WithLabelValues("zone-b", "svc-b").Get())
	require.Equal(t, 2.0, a.metrics.New.WithLabelValues("zone-b", "svc-b").Get())
	require.Equal(t, 0.0, a.metrics.Failed.WithLabelValues("zone-b", "svc-b").Get())

	a._cleanup(context.Background(), cutoff)
	require.Empty(t, a.tracker[123])
	expected := []act.ActiveConnectionTrackerKey{
		{Zone: 123, SvcID: 1},
		{Zone: 123, SvcID: 2},
		{Zone: 234, SvcID: 1},
	}
	require.ElementsMatch(t, expected, m.deletedKeys)
	require.Len(t, a.tracker[234], 1)
	// Only "zone-b", "svc-b" has updates after cut-off
	require.NotEmpty(t, a.tracker[234][2])
	require.Equal(t, 1.0, a.metrics.Active.WithLabelValues("zone-b", "svc-b").Get())
	require.Equal(t, 2.0, a.metrics.New.WithLabelValues("zone-b", "svc-b").Get())
	require.Equal(t, 0.0, a.metrics.Failed.WithLabelValues("zone-b", "svc-b").Get())

	// Confirm no metrics for other pairs
	require.Equal(t, 0.0, a.metrics.Active.WithLabelValues("zone-b", "svc-a").Get())
	require.Equal(t, 0.0, a.metrics.New.WithLabelValues("zone-b", "svc-a").Get())
	require.Equal(t, 0.0, a.metrics.Failed.WithLabelValues("zone-b", "svc-a").Get())
	require.Equal(t, 0.0, a.metrics.Active.WithLabelValues("zone-a", "svc-b").Get())
	require.Equal(t, 0.0, a.metrics.New.WithLabelValues("zone-a", "svc-b").Get())
	require.Equal(t, 0.0, a.metrics.Failed.WithLabelValues("zone-a", "svc-b").Get())
	require.Equal(t, 0.0, a.metrics.Active.WithLabelValues("zone-a", "svc-a").Get())
	require.Equal(t, 0.0, a.metrics.New.WithLabelValues("zone-a", "svc-a").Get())
	require.Equal(t, 0.0, a.metrics.Failed.WithLabelValues("zone-a", "svc-a").Get())
}

func TestOverflow(t *testing.T) {
	m := new(mapMock)
	a := newAct(hivetest.Logger(t), m, NewActiveConnectionTrackingMetrics(), &option.DaemonConfig{})

	zones := []uint8{123, 124, 125, 126, 127}
	services := make([]uint16, metricsCountSoftLimit/2)
	for i := range services {
		services[i] = uint16(i + 64)
	}

	ls := make([]int64, 0, len(zones)*len(services))
	for _, zone := range zones {
		a.tracker[zone] = make(map[uint16]*actMetric)
		for _, svc := range services {
			unix := int64(svc)*1000 + int64(zone)
			a.tracker[zone][svc] = &actMetric{
				updated: time.Unix(unix, 0),
			}
			ls = append(ls, unix)
		}
	}

	total := len(zones) * len(services)
	require.Equal(t, total, a.trackerLen())

	err := a.removeOverflow(context.Background())
	require.NoError(t, err)

	require.Equal(t, metricsCountSoftLimit, a.trackerLen())
	slices.Sort(ls)
	cutoff := ls[total-metricsCountSoftLimit]
	for _, zone := range zones {
		for _, svc := range services {
			unix := int64(svc)*1000 + int64(zone)
			if unix < cutoff {
				require.Nil(t, a.tracker[zone][svc])
			} else {
				require.NotNil(t, a.tracker[zone][svc])
			}
		}
	}
}
