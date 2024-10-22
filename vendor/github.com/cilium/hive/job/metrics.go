package job

import "time"

type Metrics interface {
	JobError(name string, err error)
	OneShotRunDuration(name string, duration time.Duration)
	TimerRunDuration(name string, duration time.Duration)
	TimerTriggerStats(name string, latency time.Duration, folds int)
	ObserverRunDuration(name string, duration time.Duration)
}

type NopMetrics struct{}

// JobError implements Metrics.
func (NopMetrics) JobError(name string, err error) {
}

// ObserverRunDuration implements Metrics.
func (NopMetrics) ObserverRunDuration(name string, duration time.Duration) {
}

// OneShotRunDuration implements Metrics.
func (NopMetrics) OneShotRunDuration(name string, duration time.Duration) {
}

// TimerRunDuration implements Metrics.
func (NopMetrics) TimerRunDuration(name string, duration time.Duration) {
}

// TimerTriggerStats implements Metrics.
func (NopMetrics) TimerTriggerStats(name string, latency time.Duration, folds int) {
}

var _ Metrics = NopMetrics{}
