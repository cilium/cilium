package logrus_fluent

import (
	"time"

	"github.com/fluent/fluent-logger-golang/fluent"
	"github.com/sirupsen/logrus"
)

// Config is settings for FluentHook.
type Config struct {
	Port                  int
	Host                  string
	LogLevels             []logrus.Level
	DisableConnectionPool bool // Fluent client will be created every logging if true.
	DefaultTag            string
	DefaultMessageField   string
	DefaultIgnoreFields   map[string]struct{}
	DefaultFilters        map[string]func(interface{}) interface{}

	// from fluent.Config
	// see https://github.com/fluent/fluent-logger-golang/blob/master/fluent/fluent.go
	FluentNetwork      string
	FluentSocketPath   string
	Timeout            time.Duration
	WriteTimeout       time.Duration
	BufferLimit        int
	RetryWait          int
	MaxRetry           int
	TagPrefix          string
	AsyncConnect       bool
	MarshalAsJSON      bool
	SubSecondPrecision bool
}

// FluentConfig converts data to fluent.Config.
func (c Config) FluentConfig() fluent.Config {
	return fluent.Config{
		FluentPort:         c.Port,
		FluentHost:         c.Host,
		FluentNetwork:      c.FluentNetwork,
		FluentSocketPath:   c.FluentSocketPath,
		Timeout:            c.Timeout,
		WriteTimeout:       c.WriteTimeout,
		BufferLimit:        c.BufferLimit,
		RetryWait:          c.RetryWait,
		MaxRetry:           c.MaxRetry,
		TagPrefix:          c.TagPrefix,
		AsyncConnect:       c.AsyncConnect,
		MarshalAsJSON:      c.MarshalAsJSON,
		SubSecondPrecision: c.SubSecondPrecision,
	}
}
