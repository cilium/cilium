// Copyright 2016-2019 Authors of Cilium
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

package endpoint

import "github.com/cilium/cilium/pkg/option"

var (
	EndpointMutableOptionLibrary = option.GetEndpointMutableOptionLibrary()
)

// ConntrackLocal determines whether this endpoint is currently using a local
// table to handle connection tracking (true), or the global table (false).
func (e *Endpoint) ConntrackLocal() bool {
	e.unconditionalRLock()
	defer e.runlock()

	return e.ConntrackLocalLocked()
}

// ConntrackLocalLocked is the same as ConntrackLocal, but assumes that the
// endpoint is already locked for reading.
func (e *Endpoint) ConntrackLocalLocked() bool {
	if e.SecurityIdentity == nil || e.Options == nil ||
		!e.Options.IsEnabled(option.ConntrackLocal) {
		return false
	}

	return true
}

// optionChanged is a callback used with pkg/option to apply the options to an
// endpoint.  Not used for anything at the moment.
func optionChanged(key string, value option.OptionSetting, data interface{}) {
}

// applyOptsLocked applies the given options to the endpoint's options and
// returns true if there were any options changed.
func (e *Endpoint) applyOptsLocked(opts option.OptionMap) bool {
	changed := e.Options.ApplyValidated(opts, optionChanged, e) > 0
	_, exists := opts[option.Debug]
	if exists && changed {
		e.UpdateLogger(nil)
	}
	return changed
}

// SetDefaultOpts initializes the endpoint Options and configures the specified
// options.
func (e *Endpoint) SetDefaultOpts(opts *option.IntOptions) {
	if e.Options == nil {
		e.Options = option.NewIntOptions(&EndpointMutableOptionLibrary)
	}
	if e.Options.Library == nil {
		e.Options.Library = &EndpointMutableOptionLibrary
	}
	if e.Options.Opts == nil {
		e.Options.Opts = option.OptionMap{}
	}

	if opts != nil {
		epOptLib := option.GetEndpointMutableOptionLibrary()
		for k := range epOptLib {
			e.Options.SetValidated(k, opts.GetValue(k))
		}
	}
	e.UpdateLogger(nil)
}

// SetDefaultConfiguration sets the default configuration options for its
// boolean configuration options and for policy enforcement based off of the
// global policy enforcement configuration options. If restore is true, then
// the configuration option to keep endpoint configuration during endpoint
// restore is checked, and if so, this is a no-op.
func (e *Endpoint) SetDefaultConfiguration(restore bool) {
	e.unconditionalLock()
	defer e.unlock()

	if restore && option.Config.KeepConfig {
		return
	}
	e.setDefaultPolicyConfig()
}
