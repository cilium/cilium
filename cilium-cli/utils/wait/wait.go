// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package wait

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/cilium-cli/defaults"
)

type LogFunc func(err error, waitTime string)

type Parameters struct {
	RetryInterval   time.Duration
	WarningInterval time.Duration
	Timeout         time.Duration
	Log             LogFunc
}

func (w Parameters) retryInterval() time.Duration {
	if w.RetryInterval != time.Duration(0) {
		return w.RetryInterval
	}

	return defaults.WaitRetryInterval
}

func (w Parameters) warningInterval() time.Duration {
	if w.WarningInterval != time.Duration(0) {
		return w.WarningInterval
	}

	return defaults.WaitWarningInterval
}

type Observer struct {
	ctx         context.Context
	params      Parameters
	lastWarning time.Time
	waitStarted time.Time
	cancel      context.CancelFunc
}

func NewObserver(ctx context.Context, p Parameters) *Observer {
	w := &Observer{
		ctx:         ctx,
		params:      p,
		waitStarted: time.Now(),
	}

	if p.Timeout != time.Duration(0) {
		w.ctx, w.cancel = context.WithTimeout(ctx, p.Timeout)
	}

	return w
}

func (w *Observer) Cancel() {
	if w.cancel != nil {
		w.cancel()
	}
}

func (w *Observer) Retry(err error) error {
	if w.params.Log != nil && time.Since(w.lastWarning) > w.params.warningInterval() {
		waitString := time.Since(w.waitStarted).Truncate(time.Second).String()
		w.params.Log(err, waitString)
		w.lastWarning = time.Now()
	}

	select {
	case <-w.ctx.Done():
		if err != nil {
			return fmt.Errorf("timeout while waiting for condition, last error: %w", err)
		}
		return fmt.Errorf("timeout while waiting for condition")
	case <-time.After(w.params.retryInterval()):
	}

	return nil
}
