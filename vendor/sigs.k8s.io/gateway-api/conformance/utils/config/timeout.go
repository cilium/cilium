/*
Copyright 2022 The Kubernetes Authors.

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

package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type TimeoutConfig struct {
	// TestIsolation represents the time block between test cases to enhance test isolation.
	// Max value for conformant implementation: None
	TestIsolation time.Duration `json:"testIsolation"`

	// CreateTimeout represents the maximum time for a Kubernetes object to be created.
	// Max value for conformant implementation: None
	CreateTimeout time.Duration `json:"createTimeout"`

	// DeleteTimeout represents the maximum time for a Kubernetes object to be deleted.
	// Max value for conformant implementation: None
	DeleteTimeout time.Duration `json:"deleteTimeout"`

	// GetTimeout represents the maximum time to get a Kubernetes object.
	// Max value for conformant implementation: None
	GetTimeout time.Duration `json:"getTimeout"`

	// GatewayMustHaveAddress represents the maximum time for at least one IP Address has been set in the status of a Gateway.
	// Max value for conformant implementation: None
	GatewayMustHaveAddress time.Duration `json:"gatewayMustHaveAddress"`

	// GatewayMustHaveCondition represents the maximum amount of time for a
	// Gateway to have the supplied Condition.
	// Max value for conformant implementation: None
	GatewayMustHaveCondition time.Duration `json:"gatewayMustHaveCondition"`

	// GatewayStatusMustHaveListeners represents the maximum time for a Gateway to have listeners in status that match the expected listeners.
	// Max value for conformant implementation: None
	GatewayStatusMustHaveListeners time.Duration `json:"gatewayStatusMustHaveListeners"`

	// GatewayListenersMustHaveConditions represents the maximum time for a Gateway to have all listeners with a specific condition.
	// Max value for conformant implementation: None
	GatewayListenersMustHaveConditions time.Duration `json:"gatewayListenersMustHaveConditions"`

	// ListenerSetMustHaveCondition represents the maximum amount of time for a
	// ListenerSet to have the supplied Condition.
	// Max value for conformant implementation: None
	ListenerSetMustHaveCondition time.Duration `json:"listenerSetMustHaveCondition"`

	// ListenerSetListenersMustHaveConditions represents the maximum time for a ListenerSet to have all listeners with a specific condition.
	// Max value for conformant implementation: None
	ListenerSetListenersMustHaveConditions time.Duration `json:"listenerSetListenersMustHaveConditions"`

	// GWCMustBeAccepted represents the maximum time for a GatewayClass to have an Accepted condition set to true.
	// Max value for conformant implementation: None
	GWCMustBeAccepted time.Duration `json:"gwcMustBeAccepted"`

	// HTTPRouteMustNotHaveParents represents the maximum time for an HTTPRoute to have either no parents or a single parent that is not accepted.
	// Max value for conformant implementation: None
	HTTPRouteMustNotHaveParents time.Duration `json:"httpRouteMustNotHaveParents"`

	// HTTPRouteMustHaveCondition represents the maximum time for an HTTPRoute to have the supplied Condition.
	// Max value for conformant implementation: None
	HTTPRouteMustHaveCondition time.Duration `json:"httpRouteMustHaveCondition"`

	// TLSRouteMustHaveCondition represents the maximum time for a TLSRoute to have the supplied Condition.
	// Max value for conformant implementation: None
	TLSRouteMustHaveCondition time.Duration `json:"tlsRouteMustHaveCondition"`

	// TCPRouteMustHaveCondition represents the maximum time for a TCPRoute to have the supplied Condition.
	// Max value for conformant implementation: None
	TCPRouteMustHaveCondition time.Duration `json:"tcpRouteMustHaveCondition"`

	// UDPRouteMustHaveCondition represents the maximum time for a UDPRoute to have the supplied Condition.
	// Max value for conformant implementation: None
	UDPRouteMustHaveCondition time.Duration `json:"udpRouteMustHaveCondition"`

	// RouteMustHaveParents represents the maximum time for an xRoute to have parents in status that match the expected parents.
	// Max value for conformant implementation: None
	RouteMustHaveParents time.Duration `json:"routeMustHaveParents"`

	// ManifestFetchTimeout represents the maximum time for getting content from a https:// URL.
	// Max value for conformant implementation: None
	ManifestFetchTimeout time.Duration `json:"manifestFetchTimeout"`

	// MaxTimeToConsistency is the maximum time for requiredConsecutiveSuccesses (default 3) requests to succeed in a row before failing the test.
	// Max value for conformant implementation: 30 seconds
	MaxTimeToConsistency time.Duration `json:"maxTimeToConsistency"`

	// NamespacesMustBeReady represents the maximum time for the following to happen within
	// specified namespace(s):
	// * All Pods to be marked as "Ready"
	// * All Gateways to be marked as "Accepted" and "Programmed"
	// Max value for conformant implementation: None
	NamespacesMustBeReady time.Duration `json:"namespacesMustBeReady"`

	// RequestTimeout represents the maximum time for making an HTTP Request with the roundtripper.
	// Max value for conformant implementation: None
	RequestTimeout time.Duration `json:"requestTimeout"`

	// LatestObservedGenerationSet represents the maximum time for an ObservedGeneration to bump.
	// Max value for conformant implementation: None
	LatestObservedGenerationSet time.Duration `json:"latestObservedGenerationSet"`

	// DefaultTestTimeout is the default amount of time to wait for a test to complete
	DefaultTestTimeout time.Duration `json:"defaultTestTimeout"`

	// DefaultPollInterval is the default amount of time to poll for status checks.
	DefaultPollInterval time.Duration `json:"defaultPollInterval"`

	// RequiredConsecutiveSuccesses is the number of requests that must succeed in a row
	// to consider a response "consistent" before making additional assertions on the response body.
	// If this number is not reached within MaxTimeToConsistency, the test will fail.
	RequiredConsecutiveSuccesses int
}

// UnmarshalJSON ensures time.Duration values are parsed correctly.
func (tc *TimeoutConfig) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	durationType := reflect.TypeFor[time.Duration]()
	v := reflect.ValueOf(tc).Elem()
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		jsonTag := strings.Split(field.Tag.Get("json"), ",")[0]
		if jsonTag == "" {
			continue
		}
		if field.Type != durationType {
			return fmt.Errorf("field %q has json tag but unsupported type %s; "+
				"TimeoutConfig.UnmarshalJSON only supports time.Duration fields", field.Name, field.Type)
		}
		val, ok := raw[jsonTag]
		if !ok {
			continue
		}
		d, err := parseDuration(val)
		if err != nil {
			return fmt.Errorf("field %q: %w", jsonTag, err)
		}
		v.Field(i).SetInt(int64(d))
	}

	return nil
}

// parseDuration accepts a duration as a string (e.g. "30s")
// or as a bare JSON number (interpreted as nanoseconds, to match the
// underlying representation of time.Duration).
func parseDuration(val any) (time.Duration, error) {
	switch x := val.(type) {
	case string:
		return time.ParseDuration(x)
	case float64:
		return time.Duration(x), nil
	default:
		return 0, fmt.Errorf("expected duration string or number, got %T", val)
	}
}

// DefaultTimeoutConfig populates a TimeoutConfig with the default values.
func DefaultTimeoutConfig() TimeoutConfig {
	return TimeoutConfig{
		CreateTimeout:                          60 * time.Second,
		DeleteTimeout:                          10 * time.Second,
		GetTimeout:                             10 * time.Second,
		GatewayMustHaveAddress:                 180 * time.Second,
		GatewayMustHaveCondition:               180 * time.Second,
		GatewayStatusMustHaveListeners:         60 * time.Second,
		GatewayListenersMustHaveConditions:     60 * time.Second,
		ListenerSetMustHaveCondition:           180 * time.Second,
		ListenerSetListenersMustHaveConditions: 60 * time.Second,
		GWCMustBeAccepted:                      180 * time.Second,
		HTTPRouteMustNotHaveParents:            60 * time.Second,
		HTTPRouteMustHaveCondition:             60 * time.Second,
		TLSRouteMustHaveCondition:              60 * time.Second,
		TCPRouteMustHaveCondition:              60 * time.Second,
		UDPRouteMustHaveCondition:              60 * time.Second,
		RouteMustHaveParents:                   60 * time.Second,
		ManifestFetchTimeout:                   10 * time.Second,
		MaxTimeToConsistency:                   30 * time.Second,
		NamespacesMustBeReady:                  300 * time.Second,
		RequestTimeout:                         10 * time.Second,
		LatestObservedGenerationSet:            60 * time.Second,
		DefaultTestTimeout:                     60 * time.Second,
		DefaultPollInterval:                    time.Millisecond * 100,
		RequiredConsecutiveSuccesses:           3,
	}
}

// ParseTimeoutOverrides parses the timeout overrides string and updates the TimeoutConfig.
func ParseTimeoutOverrides(timeoutConfig *TimeoutConfig, overrides string) {
	if overrides == "" {
		return
	}
	pairs := strings.SplitSeq(overrides, ";")
	for pair := range pairs {
		parts := strings.Split(pair, ":")
		if len(parts) != 2 {
			continue
		}
		param := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		valInt, err := strconv.Atoi(val)
		if err != nil {
			continue
		}
		overrideDuration := time.Duration(valInt) * time.Second

		switch param {
		case "CreateTimeout":
			timeoutConfig.CreateTimeout = overrideDuration
		case "DeleteTimeout":
			timeoutConfig.DeleteTimeout = overrideDuration
		case "GetTimeout":
			timeoutConfig.GetTimeout = overrideDuration
		case "GatewayMustHaveAddress":
			timeoutConfig.GatewayMustHaveAddress = overrideDuration
		case "GatewayMustHaveCondition":
			timeoutConfig.GatewayMustHaveCondition = overrideDuration
		case "GatewayStatusMustHaveListeners":
			timeoutConfig.GatewayStatusMustHaveListeners = overrideDuration
		case "GatewayListenersMustHaveConditions":
			timeoutConfig.GatewayListenersMustHaveConditions = overrideDuration
		case "ListenerSetMustHaveCondition":
			timeoutConfig.ListenerSetMustHaveCondition = overrideDuration
		case "ListenerSetListenersMustHaveConditions":
			timeoutConfig.ListenerSetListenersMustHaveConditions = overrideDuration
		case "GWCMustBeAccepted":
			timeoutConfig.GWCMustBeAccepted = overrideDuration
		case "HTTPRouteMustNotHaveParents":
			timeoutConfig.HTTPRouteMustNotHaveParents = overrideDuration
		case "HTTPRouteMustHaveCondition":
			timeoutConfig.HTTPRouteMustHaveCondition = overrideDuration
		case "TLSRouteMustHaveCondition":
			timeoutConfig.TLSRouteMustHaveCondition = overrideDuration
		case "TCPRouteMustHaveCondition":
			timeoutConfig.TCPRouteMustHaveCondition = overrideDuration
		case "UDPRouteMustHaveCondition":
			timeoutConfig.UDPRouteMustHaveCondition = overrideDuration
		case "RouteMustHaveParents":
			timeoutConfig.RouteMustHaveParents = overrideDuration
		case "ManifestFetchTimeout":
			timeoutConfig.ManifestFetchTimeout = overrideDuration
		case "MaxTimeToConsistency":
			timeoutConfig.MaxTimeToConsistency = overrideDuration
		case "NamespacesMustBeReady":
			timeoutConfig.NamespacesMustBeReady = overrideDuration
		case "RequestTimeout":
			timeoutConfig.RequestTimeout = overrideDuration
		case "LatestObservedGenerationSet":
			timeoutConfig.LatestObservedGenerationSet = overrideDuration
		case "DefaultTestTimeout":
			timeoutConfig.DefaultTestTimeout = overrideDuration
		case "DefaultPollInterval":
			timeoutConfig.DefaultPollInterval = overrideDuration
		case "RequiredConsecutiveSuccesses":
			timeoutConfig.RequiredConsecutiveSuccesses = valInt
		case "TestIsolation":
			timeoutConfig.TestIsolation = overrideDuration
		}
	}
}

func SetupTimeoutConfig(timeoutConfig *TimeoutConfig) {
	defaultTimeoutConfig := DefaultTimeoutConfig()
	if timeoutConfig.CreateTimeout == 0 {
		timeoutConfig.CreateTimeout = defaultTimeoutConfig.CreateTimeout
	}
	if timeoutConfig.DeleteTimeout == 0 {
		timeoutConfig.DeleteTimeout = defaultTimeoutConfig.DeleteTimeout
	}
	if timeoutConfig.GetTimeout == 0 {
		timeoutConfig.GetTimeout = defaultTimeoutConfig.GetTimeout
	}
	if timeoutConfig.GatewayMustHaveAddress == 0 {
		timeoutConfig.GatewayMustHaveAddress = defaultTimeoutConfig.GatewayMustHaveAddress
	}
	if timeoutConfig.GatewayMustHaveCondition == 0 {
		timeoutConfig.GatewayMustHaveCondition = defaultTimeoutConfig.GatewayMustHaveCondition
	}
	if timeoutConfig.GatewayStatusMustHaveListeners == 0 {
		timeoutConfig.GatewayStatusMustHaveListeners = defaultTimeoutConfig.GatewayStatusMustHaveListeners
	}
	if timeoutConfig.GatewayListenersMustHaveConditions == 0 {
		timeoutConfig.GatewayListenersMustHaveConditions = defaultTimeoutConfig.GatewayListenersMustHaveConditions
	}
	if timeoutConfig.ListenerSetMustHaveCondition == 0 {
		timeoutConfig.ListenerSetMustHaveCondition = defaultTimeoutConfig.ListenerSetMustHaveCondition
	}
	if timeoutConfig.ListenerSetListenersMustHaveConditions == 0 {
		timeoutConfig.ListenerSetListenersMustHaveConditions = defaultTimeoutConfig.ListenerSetListenersMustHaveConditions
	}
	if timeoutConfig.GWCMustBeAccepted == 0 {
		timeoutConfig.GWCMustBeAccepted = defaultTimeoutConfig.GWCMustBeAccepted
	}
	if timeoutConfig.HTTPRouteMustNotHaveParents == 0 {
		timeoutConfig.HTTPRouteMustNotHaveParents = defaultTimeoutConfig.HTTPRouteMustNotHaveParents
	}
	if timeoutConfig.HTTPRouteMustHaveCondition == 0 {
		timeoutConfig.HTTPRouteMustHaveCondition = defaultTimeoutConfig.HTTPRouteMustHaveCondition
	}
	if timeoutConfig.RouteMustHaveParents == 0 {
		timeoutConfig.RouteMustHaveParents = defaultTimeoutConfig.RouteMustHaveParents
	}
	if timeoutConfig.ManifestFetchTimeout == 0 {
		timeoutConfig.ManifestFetchTimeout = defaultTimeoutConfig.ManifestFetchTimeout
	}
	if timeoutConfig.MaxTimeToConsistency == 0 {
		timeoutConfig.MaxTimeToConsistency = defaultTimeoutConfig.MaxTimeToConsistency
	}
	if timeoutConfig.NamespacesMustBeReady == 0 {
		timeoutConfig.NamespacesMustBeReady = defaultTimeoutConfig.NamespacesMustBeReady
	}
	if timeoutConfig.RequestTimeout == 0 {
		timeoutConfig.RequestTimeout = defaultTimeoutConfig.RequestTimeout
	}
	if timeoutConfig.LatestObservedGenerationSet == 0 {
		timeoutConfig.LatestObservedGenerationSet = defaultTimeoutConfig.LatestObservedGenerationSet
	}
	if timeoutConfig.TLSRouteMustHaveCondition == 0 {
		timeoutConfig.TLSRouteMustHaveCondition = defaultTimeoutConfig.TLSRouteMustHaveCondition
	}
	if timeoutConfig.TCPRouteMustHaveCondition == 0 {
		timeoutConfig.TCPRouteMustHaveCondition = defaultTimeoutConfig.TCPRouteMustHaveCondition
	}
	if timeoutConfig.UDPRouteMustHaveCondition == 0 {
		timeoutConfig.UDPRouteMustHaveCondition = defaultTimeoutConfig.UDPRouteMustHaveCondition
	}
	if timeoutConfig.DefaultTestTimeout == 0 {
		timeoutConfig.DefaultTestTimeout = defaultTimeoutConfig.DefaultTestTimeout
	}
	if timeoutConfig.DefaultPollInterval == 0 {
		timeoutConfig.DefaultPollInterval = defaultTimeoutConfig.DefaultPollInterval
	}
	if timeoutConfig.RequiredConsecutiveSuccesses == 0 {
		timeoutConfig.RequiredConsecutiveSuccesses = defaultTimeoutConfig.RequiredConsecutiveSuccesses
	}
}
