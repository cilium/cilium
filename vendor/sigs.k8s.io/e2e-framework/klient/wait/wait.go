/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package wait

import (
	"time"

	apimachinerywait "k8s.io/apimachinery/pkg/util/wait"
)

const (
	defaultPollTimeout  = 5 * time.Minute
	defaultPollInterval = 5 * time.Second
)

type Options struct {
	// Interval is used to specify the poll interval while waiting for a condition to be met
	Interval time.Duration
	// Timeout is used to indicate the total time to be spent in polling for the condition
	// to be met.
	Timeout time.Duration
	// StopChan is used to setup a wait mechanism using the apimachinerywait.PollUntil method
	StopChan chan struct{}
	// Immediate is used to indicate if the apimachinerywait's immediate wait method are to be
	// called instead of the regular one
	Immediate bool
}

type Option func(*Options)

// WithTimeout sets the max timeout that the Wait checks will run trying to see if the resource under
// question has reached a final expected state. An error will be raised if the resource has not reached
// the final expected state within the time defined by this configuration
func WithTimeout(timeout time.Duration) Option {
	return func(options *Options) {
		options.Timeout = timeout
	}
}

// WithInterval configures the interval between the retries to check if a condition has been met while performing
// the polling wait on a resource under question
func WithInterval(interval time.Duration) Option {
	return func(options *Options) {
		options.Interval = interval
	}
}

// WithStopChannel provides a way to configure a Stop channel that can be used to run wait condition checks
// either until the condition has been successfully met or until the channel has been closed. This will enable
// end users to write test in cases where the max timeout is not really predictable or is a factor of a different
// configuration or event.
func WithStopChannel(stopChan chan struct{}) Option {
	return func(options *Options) {
		options.StopChan = stopChan
	}
}

// WithImmediate configures the way the Wait Checks are invoked. Setting this will invoke the condition check
// right away before the first wait for the interval kicks in. If not configured, the first check of the
// condition match will be triggered after the value configured by the WithInterval or defaultPollInterval
func WithImmediate() Option {
	return func(options *Options) {
		options.Immediate = true
	}
}

// For provides a way to perform poll checks against the kubernetes resource to make sure the resource under
// test has reached a suitable state before moving to the next action or fail with an error message.
//
// The conditions sub-packages provides a series of pre-defined wait functions that can be used by the developers
// or a custom wait function can be passed as an argument to get a similar functionality if the check required
// for your test is not already provided by the helper utility.
func For(conditionFunc apimachinerywait.ConditionFunc, opts ...Option) error {
	options := &Options{
		Interval:  defaultPollInterval,
		Timeout:   defaultPollTimeout,
		StopChan:  nil,
		Immediate: false,
	}

	for _, fn := range opts {
		fn(options)
	}

	// Setting the options.StopChan will force the usage of `PollUntil`
	if options.StopChan != nil {
		if options.Immediate {
			return apimachinerywait.PollImmediateUntil(options.Interval, conditionFunc, options.StopChan)
		}
		return apimachinerywait.PollUntil(options.Interval, conditionFunc, options.StopChan)
	}

	if options.Immediate {
		return apimachinerywait.PollImmediate(options.Interval, options.Timeout, conditionFunc)
	}
	return apimachinerywait.Poll(options.Interval, options.Timeout, conditionFunc)
}
