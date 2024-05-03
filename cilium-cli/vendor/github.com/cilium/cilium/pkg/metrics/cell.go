// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"fmt"
	"reflect"

	"github.com/cilium/hive/cell"
	"github.com/prometheus/client_golang/prometheus"

	pkgmetric "github.com/cilium/cilium/pkg/metrics/metric"
)

var Cell = cell.Module("metrics", "Metrics",
	// Provide registry to hive, but also invoke if case no cells decide to use as dependency
	cell.Provide(NewRegistry),
	Metric(NewLegacyMetrics),
	cell.Config(defaultRegistryConfig),
	cell.Invoke(func(_ *Registry) {
		// This is a hack to ensure that errors/warnings collected in the pre hive initialization
		// phase are emitted as metrics.
		FlushLoggingMetrics()
	}),
)

// Metric constructs a new metric cell.
//
// This cell type provides `S` to the hive as returned by `ctor`, it also makes each individual field
// value available via the `hive-metrics` value group. Infrastructure components such as a registry,
// inspection tool, or documentation generator can collect all metrics in the hive via this value group.
//
// The `ctor` constructor must return a struct or pointer to a struct of type `S`. The returned struct
// must only contain public fields. All field types should implement the
// `github.com/cilium/cilium/pkg/metrics/metric.WithMetadata`
// and `github.com/prometheus/client_golang/prometheus.Collector` interfaces.
func Metric[S any](ctor func() S) cell.Cell {
	var (
		withMeta  pkgmetric.WithMetadata
		collector prometheus.Collector
	)

	var nilOut S
	outTyp := reflect.TypeOf(nilOut)
	if outTyp.Kind() == reflect.Ptr {
		outTyp = outTyp.Elem()
	}

	if outTyp.Kind() != reflect.Struct {
		panic(fmt.Errorf(
			"metrics.Metric must be invoked with a constructor function that returns a struct or pointer to a struct, "+
				"a constructor which returns a %s was supplied",
			outTyp.Kind(),
		))
	}

	// Let's be strict for now, could lift this in the future if we ever need to
	if outTyp.NumField() == 0 {
		panic(fmt.Errorf(
			"metrics.Metric must be invoked with a constructor function that returns exactly a struct with at least 1 " +
				"metric, a constructor which returns a struct with zero fields was supplied",
		))
	}

	withMetaTyp := reflect.TypeOf(&withMeta).Elem()
	collectorTyp := reflect.TypeOf(&collector).Elem()
	for i := 0; i < outTyp.NumField(); i++ {
		field := outTyp.Field(i)
		if !field.IsExported() {
			panic(fmt.Errorf(
				"The struct returned by the constructor passed to metrics.Metric has a private field '%s', which "+
					"is not allowed. All fields on the returning struct must be exported",
				field.Name,
			))
		}

		if !field.Type.Implements(withMetaTyp) {
			panic(fmt.Errorf(
				"The struct returned by the constructor passed to metrics.Metric has a field '%s', which is not metric.WithMetadata.",
				field.Name,
			))
		}

		if !field.Type.Implements(collectorTyp) {
			panic(fmt.Errorf(
				"The struct returned by the constructor passed to metrics.Metric has a field '%s', which is not prometheus.Collector.",
				field.Name,
			))
		}
	}

	return cell.Provide(ctor, provideMetrics[S])
}

type hiveMetricOut struct {
	cell.Out

	Metrics []pkgmetric.WithMetadata `group:"hive-metrics,flatten"`
}

func provideMetrics[S any](metricSet S) hiveMetricOut {
	var metrics []pkgmetric.WithMetadata

	value := reflect.ValueOf(metricSet)
	typ := value.Type()
	if typ.Kind() == reflect.Pointer {
		value = value.Elem()
		typ = typ.Elem()
	}

	if typ.Kind() != reflect.Struct {
		return hiveMetricOut{}
	}

	for i := 0; i < typ.NumField(); i++ {
		if withMeta, ok := value.Field(i).Interface().(pkgmetric.WithMetadata); ok {
			metrics = append(metrics, withMeta)
		}
	}

	return hiveMetricOut{
		Metrics: metrics,
	}
}
