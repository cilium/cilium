// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"reflect"
	"runtime"

	"github.com/cilium/cilium/pkg/hive/internal"
	pkgmetric "github.com/cilium/cilium/pkg/metrics/metric"
	"go.uber.org/dig"
)

func Metric[S any](ctor func() S) Cell {
	caller := "caller"
	if _, file, no, ok := runtime.Caller(1); ok {
		caller = fmt.Sprintf("%s:%d", file, no)
	}

	var nilOut S
	outTyp := reflect.TypeOf(nilOut)
	if outTyp.Kind() == reflect.Ptr {
		outTyp = outTyp.Elem()
	}

	if outTyp.Kind() != reflect.Struct {
		panic(fmt.Sprintf(
			"cell.Metric must be invoked with a constructor function that returns a struct or pointer to a struct, "+
				"%s supplied a constructor which returns a %d",
			caller,
			outTyp.Kind(),
		))
	}

	// Lets be strict for now, could lift this in the future if we ever need to
	if outTyp.NumField() == 0 {
		panic(fmt.Sprintf(
			"cell.Metric must be invoked with a constructor function that returns exactly a struct with at least 1 "+
				"metric, %s supplied a constructor which returns a struct with zero fields",
			caller,
		))
	}

	var withMeta pkgmetric.WithMetadata
	withMetaTyp := reflect.TypeOf(&withMeta).Elem()
	for i := 0; i < outTyp.NumField(); i++ {
		field := outTyp.Field(i)
		if !field.IsExported() {
			panic(fmt.Sprintf(
				"The struct returned by the constructor passed to cell.Metric by %s has a private field '%s', which "+
					"is not allowed. All fields on the returning struct must be exported",
				caller,
				field.Name,
			))
		}

		if !field.Type.Implements(withMetaTyp) {
			panic(fmt.Sprintf(
				"The struct returned by the constructor passed to cell.Metric by %s has a field '%s', which does not "+
					"implement metric.WithMetadata.",
				caller,
				field.Name,
			))
		}
	}

	return &metric[S]{
		ctor: ctor,
	}
}

type metric[S any] struct {
	ctor func() S
}

type metricOut struct {
	dig.Out

	Metrics []pkgmetric.WithMetadata `group:"hive-metrics,flatten"`
}

func (m *metric[S]) provideMetrics(metricSet S) metricOut {
	var metrics []pkgmetric.WithMetadata

	value := reflect.ValueOf(metricSet)
	typ := value.Type()
	if typ.Kind() == reflect.Pointer {
		value = value.Elem()
		typ = typ.Elem()
	}

	if typ.Kind() != reflect.Struct {
		return metricOut{}
	}

	for i := 0; i < typ.NumField(); i++ {
		if withMeta, ok := value.Field(i).Interface().(pkgmetric.WithMetadata); ok {
			metrics = append(metrics, withMeta)
		}
	}

	return metricOut{
		Metrics: metrics,
	}
}

func (m *metric[S]) Info(container) Info {
	n := NewInfoNode(fmt.Sprintf("📈 %s", internal.FuncNameAndLocation(m.ctor)))
	n.condensed = true

	return n
}

func (m *metric[S]) Apply(container container) error {
	// Provide the supplied constructor, so its return type is directly accessible by cells
	container.Provide(m.ctor, dig.Export(true))

	// Provide the metrics provider, which will take the return value of the constructor and turn it into a
	// slice of metrics to be consumed by anyone interested in handling them.
	container.Provide(m.provideMetrics, dig.Export(true))

	return nil
}
