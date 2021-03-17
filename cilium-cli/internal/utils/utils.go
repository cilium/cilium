// Copyright 2020-2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium-cli/defaults"
)

func BuildImagePath(userImage, defaultImage, userVersion, defaultVersion string) string {
	if userImage == "" {
		userImage = defaultImage
	}

	if userVersion == "" {
		userVersion = defaultVersion
	}

	return userImage + ":" + userVersion
}

type LogFunc func(err error, waitTime string)

type WaitParameters struct {
	RetryInterval   time.Duration
	WarningInterval time.Duration
	Timeout         time.Duration
	Log             LogFunc
}

func (w WaitParameters) retryInterval() time.Duration {
	if w.RetryInterval != time.Duration(0) {
		return w.RetryInterval
	}

	return defaults.WaitRetryInterval
}

func (w WaitParameters) warningInterval() time.Duration {
	if w.WarningInterval != time.Duration(0) {
		return w.WarningInterval
	}

	return defaults.WaitWarningInterval
}

type WaitObserver struct {
	ctx         context.Context
	params      WaitParameters
	lastWarning time.Time
	waitStarted time.Time
	cancel      context.CancelFunc
}

func NewWaitObserver(ctx context.Context, p WaitParameters) *WaitObserver {
	w := &WaitObserver{
		ctx:         ctx,
		params:      p,
		lastWarning: time.Now(),
		waitStarted: time.Now(),
	}

	if p.Timeout != time.Duration(0) {
		w.ctx, w.cancel = context.WithTimeout(ctx, p.Timeout)
	}

	return w
}

func (w *WaitObserver) Cancel() {
	if w.cancel != nil {
		w.cancel()
	}
}

func (w *WaitObserver) Retry(err error) error {
	if w.params.Log != nil && time.Since(w.lastWarning) > w.params.warningInterval() {
		waitString := time.Since(w.waitStarted).Truncate(time.Second).String()
		w.params.Log(err, waitString)
		w.lastWarning = time.Now()
	}

	select {
	case <-w.ctx.Done():
		if err != nil {
			return fmt.Errorf("timeout while waiting for condition, last error: %s", err)
		}
		return fmt.Errorf("timeout while waiting for condition")
	case <-time.After(w.params.retryInterval()):
	}

	return nil
}
