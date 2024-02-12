package hive

import (
	"reflect"
	"time"

	upstream "github.com/cilium/hive"
	"github.com/sagikazarmark/slog-shim"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/cilium/hive/cell"
)

type (
	Hive       = upstream.Hive
	Shutdowner = upstream.Shutdowner
)

var (
	ShutdownWithError = upstream.ShutdownWithError
)

func moduleDecorator(id cell.ModuleID, log logrus.FieldLogger) logrus.FieldLogger {
	return log.WithField(logfields.LogSubsys, id)
}

func New(cells ...cell.Cell) *Hive {
	cells = slices.Clone(cells)
	cells = append(
		slices.Clone(cells),
		cell.SimpleHealthCell,
		cell.Provide(
			func() logrus.FieldLogger { return logging.DefaultLogger },
		))
	return upstream.NewWithOptions(
		upstream.Options{
			Logger:          slog.Default(),
			EnvPrefix:       "CILIUM_",
			ModuleDecorator: moduleDecorator,
			DecodeHooks:     decodeHooks,
			StartTimeout:    10 * time.Minute,
			StopTimeout:     10 * time.Minute,
		},
		cells...,
	)
}

var decodeHooks = cell.DecodeHooks{
	// Decode *cidr.CIDR fields
	func(from reflect.Type, to reflect.Type, data interface{}) (interface{}, error) {
		if from.Kind() != reflect.String {
			return data, nil
		}
		s := data.(string)
		if to != reflect.TypeOf((*cidr.CIDR)(nil)) {
			return data, nil
		}
		return cidr.ParseCIDR(s)
	},
}

func AddConfigOverride[Cfg cell.Flagger](h *Hive, override func(*Cfg)) {
	upstream.AddConfigOverride[Cfg](h, override)
}
