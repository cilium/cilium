// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probes

import (
	"testing"
	"time"
)

func TestKernelHZ(t *testing.T) {
	if _, err := KernelHZ(); err != nil {
		t.Fatal(err)
	}
}

func TestJiffies(t *testing.T) {
	j, err := Jiffies()
	if err != nil {
		t.Fatal(err)
	}
	if j == 0 {
		t.Fatal("unexpected zero jiffies reading")
	}
}

func TestNearest(t *testing.T) {
	var tests = []struct {
		name   string
		in     uint16
		values []uint16
		want   uint16
	}{
		{
			name:   "single value",
			in:     0,
			values: []uint16{123},
			want:   123,
		},
		{
			name:   "equal distance to multiple values",
			in:     5,
			values: []uint16{0, 10},
			want:   0,
		},
		{
			name:   "in higher than last value",
			in:     20,
			values: []uint16{0, 10},
			want:   10,
		},
		{
			name:   "in lower than first value",
			in:     0,
			values: []uint16{10, 20},
			want:   10,
		},
		{
			name:   "in max value",
			in:     ^uint16(0),
			values: []uint16{10, 20},
			want:   20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := nearest(tt.in, tt.values)
			if err != nil {
				t.Error(err)
			}
			if want, got := tt.want, n; want != got {
				t.Errorf("expected %d, got %d", want, got)
			}
		})
	}

	if _, err := nearest(0, nil); err == nil {
		t.Fatal("expected nearest with empty values to return error")
	}
}

func mustParse(tb testing.TB, value string) time.Time {
	t, err := time.Parse(time.StampMilli, value)
	if err != nil {
		tb.Fatal(err)
	}
	return t
}

func TestKtimeInterpolate(t *testing.T) {
	var tests = []struct {
		name string
		k1   ktime
		k2   ktime
		hz   uint16
	}{
		{
			name: "10 jiffies over 10 milliseconds = 1000 hz",
			k1: ktime{
				k: 0,
				t: mustParse(t, "Jan 01 00:00:00.000"),
			},
			k2: ktime{
				k: 10,
				t: mustParse(t, "Jan 01 00:00:00.010"),
			},
			hz: 1000,
		},
		{
			name: "100 jiffies over 123 milliseconds = 813 hz",
			k1: ktime{
				k: 100,
				t: mustParse(t, "Jan 01 00:00:00.000"),
			},
			k2: ktime{
				k: 200,
				t: mustParse(t, "Jan 01 00:00:00.123"),
			},
			hz: 813,
		},
		{
			name: "1 jiffy over 1 second = 1 hz",
			k1: ktime{
				k: 100,
				t: mustParse(t, "Jan 01 00:00:00.000"),
			},
			k2: ktime{
				k: 101,
				t: mustParse(t, "Jan 01 00:00:01.000"),
			},
			hz: 1,
		},
		{
			name: "0 jiffies over 1 second = 0 hz",
			k1: ktime{
				k: 100,
				t: mustParse(t, "Jan 01 00:00:00.000"),
			},
			k2: ktime{
				k: 100,
				t: mustParse(t, "Jan 01 00:00:01.000"),
			},
			hz: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.k1.interpolate(tt.k2)
			if err != nil {
				t.Error(err)
			}

			if want, got := tt.hz, got; want != got {
				t.Errorf("expected %d hz, got %d hz", want, got)
			}
		})
	}
}

func TestKtimeInterpolateErrors(t *testing.T) {
	t1 := ktime{t: mustParse(t, "Jan 01 00:00:01.000")}
	t2 := ktime{t: mustParse(t, "Jan 01 00:00:00.000")}

	if _, err := t1.interpolate(t2); err == nil {
		t.Error("expected error interpolating ktimes with descending time.Time")
	}

	t1 = ktime{k: 1}
	t2 = ktime{k: 0}

	if _, err := t1.interpolate(t2); err == nil {
		t.Error("expected error interpolating ktimes with descending jiffies")
	}
}
