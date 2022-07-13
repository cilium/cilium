/*
 *
 * Copyright 2022 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Package outlierdetection provides an implementation of the outlier detection
// LB policy, as defined in
// https://github.com/grpc/proposal/blob/master/A50-xds-outlier-detection.md.
package outlierdetection

import (
	"encoding/json"
	"errors"
	"fmt"

	"google.golang.org/grpc/balancer"
	"google.golang.org/grpc/internal"
	"google.golang.org/grpc/internal/envconfig"
	"google.golang.org/grpc/serviceconfig"
)

// Name is the name of the outlier detection balancer.
const Name = "outlier_detection_experimental"

func init() {
	if envconfig.XDSOutlierDetection {
		balancer.Register(bb{})
	}
	// TODO: Remove these once the Outlier Detection env var is removed.
	internal.RegisterOutlierDetectionBalancerForTesting = func() {
		balancer.Register(bb{})
	}
	internal.UnregisterOutlierDetectionBalancerForTesting = func() {
		internal.BalancerUnregister(Name)
	}
}

type bb struct{}

func (bb) Build(cc balancer.ClientConn, bOpts balancer.BuildOptions) balancer.Balancer {
	return nil
}

func (bb) ParseConfig(s json.RawMessage) (serviceconfig.LoadBalancingConfig, error) {
	var lbCfg *LBConfig
	if err := json.Unmarshal(s, &lbCfg); err != nil { // Validates child config if present as well.
		return nil, fmt.Errorf("xds: unable to unmarshal LBconfig: %s, error: %v", string(s), err)
	}

	// Note: in the xds flow, these validations will never fail. The xdsclient
	// performs the same validations as here on the xds Outlier Detection
	// resource before parsing into the internal struct which gets marshaled
	// into JSON before calling this function. A50 defines two separate places
	// for these validations to take place, the xdsclient and this ParseConfig
	// method. "When parsing a config from JSON, if any of these requirements is
	// violated, that should be treated as a parsing error." - A50

	switch {
	// "The google.protobuf.Duration fields interval, base_ejection_time, and
	// max_ejection_time must obey the restrictions in the
	// google.protobuf.Duration documentation and they must have non-negative
	// values." - A50
	// Approximately 290 years is the maximum time that time.Duration (int64)
	// can represent. The restrictions on the protobuf.Duration field are to be
	// within +-10000 years. Thus, just check for negative values.
	case lbCfg.Interval < 0:
		return nil, fmt.Errorf("OutlierDetectionLoadBalancingConfig.interval = %s; must be >= 0", lbCfg.Interval)
	case lbCfg.BaseEjectionTime < 0:
		return nil, fmt.Errorf("OutlierDetectionLoadBalancingConfig.base_ejection_time = %s; must be >= 0", lbCfg.BaseEjectionTime)
	case lbCfg.MaxEjectionTime < 0:
		return nil, fmt.Errorf("OutlierDetectionLoadBalancingConfig.max_ejection_time = %s; must be >= 0", lbCfg.MaxEjectionTime)
	// "The fields max_ejection_percent,
	// success_rate_ejection.enforcement_percentage,
	// failure_percentage_ejection.threshold, and
	// failure_percentage.enforcement_percentage must have values less than or
	// equal to 100." - A50
	case lbCfg.MaxEjectionPercent > 100:
		return nil, fmt.Errorf("OutlierDetectionLoadBalancingConfig.max_ejection_percent = %v; must be <= 100", lbCfg.MaxEjectionPercent)
	case lbCfg.SuccessRateEjection != nil && lbCfg.SuccessRateEjection.EnforcementPercentage > 100:
		return nil, fmt.Errorf("OutlierDetectionLoadBalancingConfig.SuccessRateEjection.enforcement_percentage = %v; must be <= 100", lbCfg.SuccessRateEjection.EnforcementPercentage)
	case lbCfg.FailurePercentageEjection != nil && lbCfg.FailurePercentageEjection.Threshold > 100:
		return nil, fmt.Errorf("OutlierDetectionLoadBalancingConfig.FailurePercentageEjection.threshold = %v; must be <= 100", lbCfg.FailurePercentageEjection.Threshold)
	case lbCfg.FailurePercentageEjection != nil && lbCfg.FailurePercentageEjection.EnforcementPercentage > 100:
		return nil, fmt.Errorf("OutlierDetectionLoadBalancingConfig.FailurePercentageEjection.enforcement_percentage = %v; must be <= 100", lbCfg.FailurePercentageEjection.EnforcementPercentage)
	case lbCfg.ChildPolicy == nil:
		return nil, errors.New("OutlierDetectionLoadBalancingConfig.child_policy must be present")
	}

	return lbCfg, nil
}

func (bb) Name() string {
	return Name
}
