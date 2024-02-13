package hive

import (
	"log/slog"
	"os"
	"reflect"
	"strings"
	"time"

	upstream "github.com/cilium/hive"
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

	// Custom slog logger that has output that matches with logrus.
	// TODO: Might be easier to write a slog handler that uses logrus
	// as the initial version?
	// TODO: JSON and syslog support.
	slogLogger = slog.New(slog.NewTextHandler(
		os.Stdout,
		&slog.HandlerOptions{
			AddSource: false,
			Level:     nil,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				switch a.Key {
				case "time":
					// Drop timestamps
					return slog.Attr{}
				case "level":
					// Lower-case the log level
					return slog.Attr{
						Key:   a.Key,
						Value: slog.StringValue(strings.ToLower(a.Value.String())),
					}
				}
				return a
			},
		},
	))
)

func moduleDecorator(id cell.ModuleID, log logrus.FieldLogger) logrus.FieldLogger {
	return log.WithField(logfields.LogSubsys, id)
}

// New wraps the hive.New to create a hive with defaults used by cilium-agent.
// pkg/hive should eventually go away and this code should live in e.g. daemon/cmd
// or operator/cmd.
func New(cells ...cell.Cell) *Hive {
	cells = append(
		slices.Clone(cells),
		cell.SimpleHealthCell,
		cell.Provide(
			func() logrus.FieldLogger { return logging.DefaultLogger },
		))
	return upstream.NewWithOptions(
		upstream.Options{
			Logger:          slogLogger.With(logfields.LogSubsys, "hive"),
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
