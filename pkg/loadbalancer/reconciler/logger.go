// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/time"
)

const (
	// The amount of time to wait between log messages
	logRateInterval = time.Second / 2

	// The number of log messages to allow in burst when
	// the [logRateInterval] has elapsed.
	logRateBurst = 10
)

// rateLimitingLogger wraps [slog.Logger] and discards log messages
// above a specific rate.
type rateLimitingLogger struct {
	limiter logging.Limiter
	log     *slog.Logger
}

func newRateLimitingLogger(log *slog.Logger) rateLimitingLogger {
	return rateLimitingLogger{
		log:     log,
		limiter: logging.NewLimiter(logRateInterval, logRateBurst),
	}
}

func (log rateLimitingLogger) Debug(msg string, args ...any) {
	// Debug messages are not rate limited.
	log.log.Debug(msg, args...)
}

func (log rateLimitingLogger) Info(msg string, args ...any) {
	if log.limiter.Allow() {
		log.log.Info(msg, args...)
	}
}

func (log rateLimitingLogger) Warn(msg string, args ...any) {
	if log.limiter.Allow() {
		log.log.Warn(msg, args...)
	}
}
