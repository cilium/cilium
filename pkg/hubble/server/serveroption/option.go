// Copyright 2020 Authors of Hubble
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

package serveroption

import (
	"context"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/filters"

	"github.com/sirupsen/logrus"
)

// CiliumDaemon is a reference to the Cilium's Daemon when running inside Cilium
type CiliumDaemon interface {
	DebugEnabled() bool
}

// Server gives access to the Hubble server
type Server interface {
	GetOptions() Options
	GetLogger() *logrus.Entry
}

// Default serves only as reference point for default values. Very useful for
// the CLI to pick these up instead of defining own defaults that need to be
// kept in sync.
var Default = Options{
	MaxFlows:      131071, // 2^17-1
	MonitorBuffer: 1024,
}

// Options stores all the configurations values for the hubble server.
type Options struct {
	// Both sizes should really be uint32 but it's better saved for a single
	// refactor commit.
	MaxFlows      int // max number of flows that can be stored in the ring buffer
	MonitorBuffer int // buffer size for monitor payload

	CiliumDaemon CiliumDaemon // when running inside Cilium, contains a reference to the daemon

	OnServerInit   []OnServerInit          // invoked when the hubble server is initialized
	OnMonitorEvent []OnMonitorEvent        // invoked before an event is decoded
	OnDecodedFlow  []OnDecodedFlow         // invoked after a flow has been decoded
	OnBuildFilter  []filters.OnBuildFilter // invoked while building a flow filter
}

// returning `stop: true` from a callback stops the execution chain, regardless
// of the error encountered (for example, explicitly filtering out certain
// events, or similar).
type stop = bool

// Option customizes the configuration of the hubble server.
type Option func(o *Options) error

// OnServerInit is invoked after all server options have been applied
type OnServerInit interface {
	OnServerInit(Server) error
}

// OnServerInitFunc implements OnServerInit for a single function
type OnServerInitFunc func(Server) error

// OnServerInit is invoked after all server options have been applied
func (f OnServerInitFunc) OnServerInit(srv Server) error {
	return f(srv)
}

// OnMonitorEvent is invoked before each monitor event is decoded
type OnMonitorEvent interface {
	OnMonitorEvent(context.Context, *pb.Payload) (stop, error)
}

// OnMonitorEventFunc implements OnMonitorEvent for a single function
type OnMonitorEventFunc func(context.Context, *pb.Payload) (stop, error)

// OnMonitorEvent is invoked before each monitor event is decoded
func (f OnMonitorEventFunc) OnMonitorEvent(ctx context.Context, payload *pb.Payload) (stop, error) {
	return f(ctx, payload)
}

// OnDecodedFlow is invoked after a flow has been decoded
type OnDecodedFlow interface {
	OnDecodedFlow(context.Context, *pb.Flow) (stop, error)
}

// OnDecodedFlowFunc implements OnDecodedFlow for a single function
type OnDecodedFlowFunc func(context.Context, *pb.Flow) (stop, error)

// OnDecodedFlow is invoked after a flow has been decoded
func (f OnDecodedFlowFunc) OnDecodedFlow(ctx context.Context, flow *pb.Flow) (stop, error) {
	return f(ctx, flow)
}

// WithMonitorBuffer controls the size of the buffered channel between the
// monitor socket and the hubble ring buffer.
func WithMonitorBuffer(size int) Option {
	return func(o *Options) error {
		o.MonitorBuffer = size
		return nil
	}
}

// WithMaxFlows that the ring buffer is initialized to hold.
func WithMaxFlows(size int) Option {
	return func(o *Options) error {
		o.MaxFlows = size
		return nil
	}
}

// WithCiliumDaemon provides access to the Cilium daemon via downcast
func WithCiliumDaemon(daemon CiliumDaemon) Option {
	return func(o *Options) error {
		o.CiliumDaemon = daemon
		return nil
	}
}

// WithOnServerInit adds a new callback to be invoked after server initialization
func WithOnServerInit(f OnServerInit) Option {
	return func(o *Options) error {
		o.OnServerInit = append(o.OnServerInit, f)
		return nil
	}
}

// WithOnServerInitFunc adds a new callback to be invoked after server initialization
func WithOnServerInitFunc(f func(Server) error) Option {
	return WithOnServerInit(OnServerInitFunc(f))
}

// WithOnMonitorEvent adds a new callback to be invoked before decoding
func WithOnMonitorEvent(f OnMonitorEvent) Option {
	return func(o *Options) error {
		o.OnMonitorEvent = append(o.OnMonitorEvent, f)
		return nil
	}
}

// WithOnMonitorEventFunc adds a new callback to be invoked before decoding
func WithOnMonitorEventFunc(f func(context.Context, *pb.Payload) (stop, error)) Option {
	return WithOnMonitorEvent(OnMonitorEventFunc(f))
}

// WithOnDecodedFlow adds a new callback to be invoked after decoding
func WithOnDecodedFlow(f OnDecodedFlow) Option {
	return func(o *Options) error {
		o.OnDecodedFlow = append(o.OnDecodedFlow, f)
		return nil
	}
}

// WithOnDecodedFlowFunc adds a new callback to be invoked after decoding
func WithOnDecodedFlowFunc(f func(context.Context, *pb.Flow) (stop, error)) Option {
	return WithOnDecodedFlow(OnDecodedFlowFunc(f))
}

// WithOnBuildFilter adds a new callback to be invoked while building a flow filter
func WithOnBuildFilter(f filters.OnBuildFilter) Option {
	return func(o *Options) error {
		o.OnBuildFilter = append(o.OnBuildFilter, f)
		return nil
	}
}

// WithOnBuildFilterFunc adds a new callback to be invoked while building flow filters
func WithOnBuildFilterFunc(f filters.OnBuildFilterFunc) Option {
	return WithOnBuildFilter(filters.OnBuildFilterFunc(f))
}
