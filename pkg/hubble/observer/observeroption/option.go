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

package observeroption

import (
	"context"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/hubble/container"
	"github.com/cilium/cilium/pkg/hubble/filters"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"

	"github.com/sirupsen/logrus"
)

// CiliumDaemon is a reference to the Cilium's Daemon when running inside Cilium
type CiliumDaemon interface {
	DebugEnabled() bool
	// CiliumDaemon implements the StoreGetter interface that exposes cached stores
	// of various k8s resources.
	// WARNING: Access to the stores are meant to be read-only. Do not modify the stores
	// or any objects returned by the stores.
	getters.StoreGetter
}

// Server gives access to the Hubble server
type Server interface {
	GetOptions() Options
	GetLogger() logrus.FieldLogger
}

// Options stores all the configurations values for the hubble server.
type Options struct {
	MaxFlows      container.Capacity // max number of flows that can be stored in the ring buffer
	MonitorBuffer int                // buffer size for monitor payload

	CiliumDaemon CiliumDaemon // when running inside Cilium, contains a reference to the daemon

	OnServerInit   []OnServerInit          // invoked when the hubble server is initialized
	OnMonitorEvent []OnMonitorEvent        // invoked before an event is decoded
	OnDecodedFlow  []OnDecodedFlow         // invoked after a flow has been decoded
	OnBuildFilter  []filters.OnBuildFilter // invoked while building a flow filter
	OnFlowDelivery []OnFlowDelivery        // invoked before a flow is delivered via API
	OnGetFlows     []OnGetFlows            // invoked on new GetFlows API call
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
	OnMonitorEvent(context.Context, *observerTypes.MonitorEvent) (stop, error)
}

// OnMonitorEventFunc implements OnMonitorEvent for a single function
type OnMonitorEventFunc func(context.Context, *observerTypes.MonitorEvent) (stop, error)

// OnMonitorEvent is invoked before each monitor event is decoded
func (f OnMonitorEventFunc) OnMonitorEvent(ctx context.Context, event *observerTypes.MonitorEvent) (stop, error) {
	return f(ctx, event)
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

// OnFlowDelivery is invoked before a flow is delivered via the API
type OnFlowDelivery interface {
	OnFlowDelivery(context.Context, *pb.Flow) (stop, error)
}

// OnFlowDeliveryFunc implements OnFlowDelivery for a single function
type OnFlowDeliveryFunc func(context.Context, *pb.Flow) (stop, error)

// OnFlowDelivery is invoked before a flow is delivered via the API
func (f OnFlowDeliveryFunc) OnFlowDelivery(ctx context.Context, flow *pb.Flow) (stop, error) {
	return f(ctx, flow)
}

// OnGetFlows is invoked for each GetFlows call
type OnGetFlows interface {
	OnGetFlows(context.Context, *observer.GetFlowsRequest) (context.Context, error)
}

// OnGetFlowsFunc implements OnGetFlows for a single function
type OnGetFlowsFunc func(context.Context, *observer.GetFlowsRequest) (context.Context, error)

// OnGetFlows is invoked for each GetFlows call
func (f OnGetFlowsFunc) OnGetFlows(ctx context.Context, req *observer.GetFlowsRequest) (context.Context, error) {
	return f(ctx, req)
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
func WithMaxFlows(capacity container.Capacity) Option {
	return func(o *Options) error {
		o.MaxFlows = capacity
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
func WithOnMonitorEventFunc(f func(context.Context, *observerTypes.MonitorEvent) (stop, error)) Option {
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

// WithOnFlowDelivery adds a new callback to be invoked before a flow is delivered via the API
func WithOnFlowDelivery(f OnFlowDelivery) Option {
	return func(o *Options) error {
		o.OnFlowDelivery = append(o.OnFlowDelivery, f)
		return nil
	}
}

// WithOnFlowDeliveryFunc adds a new callback to be invoked before a flow is delivered via the API
func WithOnFlowDeliveryFunc(f OnFlowDeliveryFunc) Option {
	return WithOnFlowDelivery(f)
}

// WithOnGetFlows adds a new callback to be invoked for each GetFlows call
func WithOnGetFlows(f OnGetFlows) Option {
	return func(o *Options) error {
		o.OnGetFlows = append(o.OnGetFlows, f)
		return nil
	}
}

// WithOnGetFlowsFunc adds a new callback to be invoked for each GetFlows call
func WithOnGetFlowsFunc(f OnGetFlowsFunc) Option {
	return WithOnGetFlows(f)
}
