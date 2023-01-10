// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package observer

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/hubble/relay/defaults"
	poolTypes "github.com/cilium/cilium/pkg/hubble/relay/pool/types"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type observerClientBuilder interface {
	observerClient(p *poolTypes.Peer) observerpb.ObserverClient
}

type defaultObserverClientBuilder struct{}

func (d defaultObserverClientBuilder) observerClient(p *poolTypes.Peer) observerpb.ObserverClient {
	if p == nil {
		return nil
	}
	if conn, ok := p.Conn.(*grpc.ClientConn); ok {
		return observerpb.NewObserverClient(conn)
	}
	return nil
}

// DefaultOptions is the reference point for default values.
var defaultOptions = options{
	sortBufferMaxLen:       defaults.SortBufferMaxLen,
	sortBufferDrainTimeout: defaults.SortBufferDrainTimeout,
	errorAggregationWindow: defaults.ErrorAggregationWindow,
	log:                    logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble-relay"),
	ocb:                    defaultObserverClientBuilder{},
}

// Option customizes the configuration of the Manager.
type Option func(o *options) error

// Options stores all the configuration values for peer manager.
type options struct {
	sortBufferMaxLen       int
	sortBufferDrainTimeout time.Duration
	errorAggregationWindow time.Duration
	log                    logrus.FieldLogger

	// this is not meant to be user configurable as it's only useful to
	// override when testing
	ocb observerClientBuilder
}

// WithSortBufferMaxLen sets the maximum number of flows that can be buffered
// for sorting before being sent to the client. The provided value must be
// greater than 0 and is to be understood per client request. Therefore, it is
// advised to keep the value moderate (a value between 30 and 100 should
// constitute a good choice in most cases).
func WithSortBufferMaxLen(i int) Option {
	return func(o *options) error {
		if i <= 0 {
			return fmt.Errorf("value for SortBufferMaxLen must be greater than 0: %d", i)
		}
		o.sortBufferMaxLen = i
		return nil
	}
}

// WithSortBufferDrainTimeout sets the sort buffer drain timeout value. For
// flows requests where the total number of flows cannot be determined
// (typically for flows requests in follow mode), a flow is taken out of the
// buffer and sent to the client after duration d if the buffer is not full.
// This value must be greater than 0. Setting this value too low would render
// the flows sorting operation ineffective. A value between 500 milliseconds
// and 3 seconds should be constitute a good choice in most cases.
func WithSortBufferDrainTimeout(d time.Duration) Option {
	return func(o *options) error {
		if d <= 0 {
			return fmt.Errorf("value for SortBufferDrainTimeout must be greater than 0: %d", d)
		}
		o.sortBufferDrainTimeout = d
		return nil
	}
}

// WithErrorAggregationWindow sets a time window during which errors with the
// same error message are coalesced. The aggregated error is forwarded to the
// downstream consumer either when the window expires or when a new, different
// error occurs (whichever happens first)
func WithErrorAggregationWindow(d time.Duration) Option {
	return func(o *options) error {
		if d <= 0 {
			return fmt.Errorf("value for ErrorAggregationWindow must be greater than 0: %d", d)
		}
		o.errorAggregationWindow = d
		return nil
	}
}

// WithLogger sets the logger to use for logging.
func WithLogger(l logrus.FieldLogger) Option {
	return func(o *options) error {
		o.log = l
		return nil
	}
}

// withObserverClientBuilder sets the observerClientBuilder that is used to
// create a new ObserverClient from a poolTypes.ClientConn. This is private as
// it is only useful to override the default in the context of implemeting unit
// tests.
func withObserverClientBuilder(b observerClientBuilder) Option {
	return func(o *options) error {
		o.ocb = b
		return nil
	}
}
