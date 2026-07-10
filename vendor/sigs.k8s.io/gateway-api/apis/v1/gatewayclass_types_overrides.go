/*
Copyright 2024 The Kubernetes Authors.

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

package v1

import (
	"encoding/json"
	"errors"
)

// Below code handles the experimental field breaking change introduced in
// https://github.com/kubernetes-sigs/gateway-api/pull/3200/.
// We are overriding the UnmarshalJSON function to be able to handle cases where
// users had the old version of the GatewayClass CRD applied with SupportedFeatures
// as a list of strings and not list of objects.
// See https://github.com/kubernetes-sigs/gateway-api/issues/3464
// for more information.

func (s *SupportedFeature) UnmarshalJSON(data []byte) error {
	var oldSupportedFeature oldSupportedFeature
	var unmarshalTypeErr *json.UnmarshalTypeError
	if err := json.Unmarshal(data, &oldSupportedFeature); err == nil {
		s.Name = FeatureName(oldSupportedFeature)
		return nil
	} else if !errors.As(err, &unmarshalTypeErr) {
		// If the error is not a type error, return it
		return err
	}

	var si supportedFeatureInternal
	if err := json.Unmarshal(data, &si); err != nil {
		return err
	}
	s.Name = si.Name
	return nil
}

// This is solely for the purpose of ensuring backward compatibility and
// SHOULD NOT be used elsewhere.
type supportedFeatureInternal struct {
	// +required
	Name FeatureName `json:"name"`
}

// This is solely for the purpose of ensuring backward compatibility and
// SHOULD NOT be used elsewhere.
type oldSupportedFeature string
