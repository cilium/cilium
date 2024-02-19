package job

import (
	upstream "github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/stream"
)

type (
	Group              = upstream.Group
	Registry           = upstream.Registry
	Job                = upstream.Job
	ScopedGroup        = upstream.ScopedGroup
	ExponentialBackoff = upstream.ExponentialBackoff
)

var (
	Cell            = upstream.Cell
	OneShot         = upstream.OneShot
	Timer           = upstream.Timer
	WithLogger      = upstream.WithLogger
	WithPprofLabels = upstream.WithPprofLabels
	WithRetry       = upstream.WithRetry
	WithShutdown    = upstream.WithShutdown
)

func Observer[T any](name string, fn upstream.ObserverFunc[T], observable stream.Observable[T]) Job {
	return upstream.Observer(name, fn, observable)
}
