// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicesync

import (
	"reflect"

	"github.com/blang/semver/v4"
	"github.com/prometheus/client_golang/prometheus"
	k8smetrics "k8s.io/component-base/metrics"
	endpointslicemetrics "k8s.io/endpointslice/metrics"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type Metrics struct {
	// EndpointsAddedPerSync tracks the number of endpoints added on each
	// Service sync.
	EndpointsAddedPerSync metric.Vec[metric.Observer]
	// EndpointsRemovedPerSync tracks the number of endpoints removed on each
	// Service sync.
	EndpointsRemovedPerSync metric.Vec[metric.Observer]
	// EndpointSlicesChangedPerSync observes the number of EndpointSlices
	// changed per sync.
	EndpointSlicesChangedPerSync metric.Vec[metric.Observer]
	// EndpointSliceChanges tracks the number of changes to Endpoint Slices.
	EndpointSliceChanges metric.Vec[metric.Counter]
	// EndpointSliceSyncs tracks the number of sync operations the controller
	// runs along with their result.
	EndpointSliceSyncs metric.Vec[metric.Counter]
	// NumEndpointSlices tracks the number of EndpointSlices in a cluster.
	NumEndpointSlices metric.Vec[metric.Gauge]
	// DesiredEndpointSlices tracks the number of EndpointSlices that would
	// exist with perfect endpoint allocation.
	DesiredEndpointSlices metric.Vec[metric.Gauge]
	// EndpointsDesired tracks the total number of desired endpoints.
	EndpointsDesired metric.Vec[metric.Gauge]
}

// linkGaugeVec uses reflection to force gauge vec to be the same pointer from
// kubernetes GaugeVec and cilium GaugeVec so that Kubernetes code can add data and
// Cilium is able to register them.
func linkGaugeVec(k8sGaugeVec *k8smetrics.GaugeVec, ciliumGaugeVec metric.Vec[metric.Gauge]) {
	version := semver.MustParse("1.0.0") // This is not really used as we override it later anyway
	k8sGaugeVec.Create(&version)
	k8sGaugeVec.GaugeVec = (*prometheus.GaugeVec)(
		reflect.ValueOf(ciliumGaugeVec).Elem().FieldByName("GaugeVec").UnsafePointer(),
	)
}

// linkCounterVec uses reflection to force gauge vec to be the same pointer from
// kubernetes CounterVec and cilium CounterVec so that Kubernetes code can add data and
// Cilium is able to register them.
func linkCounterVec(k8sCounterVec *k8smetrics.CounterVec, ciliumCounterVec metric.Vec[metric.Counter]) {
	version := semver.MustParse("1.0.0") // This is not really used as we override it later anyway
	k8sCounterVec.Create(&version)
	k8sCounterVec.CounterVec = (*prometheus.CounterVec)(
		reflect.ValueOf(ciliumCounterVec).Elem().FieldByName("CounterVec").UnsafePointer(),
	)
}

// linkHistogramVec uses reflection to force gauge vec to be the same pointer from
// kubernetes HistogramVec and cilium HistogramVec so that Kubernetes code can add data and
// Cilium is able to register them.
func linkHistogramVec(k8sHistogramVec *k8smetrics.HistogramVec, ciliumHistogramVec metric.Vec[metric.Observer]) {
	version := semver.MustParse("1.0.0") // This is not really used as we override it later anyway
	k8sHistogramVec.Create(&version)
	k8sHistogramVec.HistogramVec = (*prometheus.HistogramVec)(
		reflect.ValueOf(ciliumHistogramVec).Elem().FieldByName("ObserverVec").Elem().UnsafePointer(),
	)
}

func NewMetrics() Metrics {
	endpointsAddedPerSync := metric.NewHistogramVec(
		metric.HistogramOpts{
			Namespace:                      metrics.CiliumOperatorNamespace,
			Subsystem:                      subsystem,
			Name:                           "endpoints_added_per_sync",
			Help:                           "Number of endpoints added on each Service sync",
			NativeHistogramBucketFactor:    2,
			NativeHistogramZeroThreshold:   2,
			NativeHistogramMaxBucketNumber: 15,
		},
		[]string{},
	)
	linkHistogramVec(endpointslicemetrics.EndpointsAddedPerSync, endpointsAddedPerSync)

	endpointsRemovedPerSync := metric.NewHistogramVec(
		metric.HistogramOpts{
			Namespace:                      metrics.CiliumOperatorNamespace,
			Subsystem:                      subsystem,
			Name:                           "endpoints_removed_per_sync",
			Help:                           "Number of endpoints removed on each Service sync",
			NativeHistogramBucketFactor:    2,
			NativeHistogramZeroThreshold:   2,
			NativeHistogramMaxBucketNumber: 15,
		},
		[]string{},
	)
	linkHistogramVec(endpointslicemetrics.EndpointsRemovedPerSync, endpointsRemovedPerSync)

	endpointsDesired := metric.NewGaugeVec(
		metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Subsystem: subsystem,
			Name:      "endpoints_desired",
			Help:      "Number of endpoints desired",
		},
		[]string{},
	)
	linkGaugeVec(endpointslicemetrics.EndpointsDesired, endpointsDesired)

	numEndpointSlices := metric.NewGaugeVec(
		metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Subsystem: subsystem,
			Name:      "num_endpoint_slices",
			Help:      "Number of endpoints desired",
		},
		[]string{},
	)
	linkGaugeVec(endpointslicemetrics.NumEndpointSlices, numEndpointSlices)

	desiredEndpointSlices := metric.NewGaugeVec(
		metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Subsystem: subsystem,
			Name:      "desired_endpoint_slices",
			Help:      "Number of EndpointSlices that would exist with perfect endpoint allocation",
		},
		[]string{},
	)
	linkGaugeVec(endpointslicemetrics.DesiredEndpointSlices, desiredEndpointSlices)

	endpointSliceChanges := metric.NewCounterVec(
		metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Subsystem: subsystem,
			Name:      "endpoint_slice_changes",
			Help:      "Number of EndpointSlice changes",
		},
		[]string{"operation"},
	)
	linkCounterVec(endpointslicemetrics.EndpointSliceChanges, endpointSliceChanges)

	endpointSlicesChangedPerSync := metric.NewHistogramVec(
		metric.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Subsystem: subsystem,
			Name:      "endpointslices_changed_per_sync",
			Help:      "Number of EndpointSlices changed on each Service sync",
		},
		[]string{"topology"},
	)
	linkHistogramVec(endpointslicemetrics.EndpointSlicesChangedPerSync, endpointSlicesChangedPerSync)

	endpointSliceSyncs := metric.NewCounterVec(
		metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Subsystem: subsystem,
			Name:      "endpoint_slice_syncs",
			Help:      "Number of EndpointSlice syncs",
		},
		[]string{"result"}, // either "success", "stale", or "error"
	)
	linkCounterVec(endpointslicemetrics.EndpointSliceSyncs, endpointSliceSyncs)

	return Metrics{
		EndpointsAddedPerSync:        endpointsAddedPerSync,
		EndpointsRemovedPerSync:      endpointsRemovedPerSync,
		EndpointsDesired:             endpointsDesired,
		NumEndpointSlices:            numEndpointSlices,
		DesiredEndpointSlices:        desiredEndpointSlices,
		EndpointSliceChanges:         endpointSliceChanges,
		EndpointSlicesChangedPerSync: endpointSlicesChangedPerSync,
		EndpointSliceSyncs:           endpointSliceSyncs,
	}
}
