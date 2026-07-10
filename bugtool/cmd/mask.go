// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"encoding/json"
	"slices"
)

const (
	redacted = "[redacted]"
	ident    = "\t"
)

// jsonFieldMaskPostProcess returns a postProcessFunc that masks the specified field names.
// The input byte slice is expected to be a JSON object.
func jsonFieldMaskPostProcess(fieldNames []string) postProcessFunc {
	return func(b []byte) ([]byte, error) {
		return maskFields(b, fieldNames)
	}
}

func maskFields(b []byte, fieldNames []string) ([]byte, error) {
	var data map[string]any

	if err := json.Unmarshal(b, &data); err != nil {
		return nil, err
	}

	mask(data, fieldNames)

	// MarshalIndent is used to make the output more readable.
	return json.MarshalIndent(data, "", ident)
}

func mask(data map[string]any, fieldNames []string) {
	for k, v := range data {
		if slices.Contains(fieldNames, k) {
			data[k] = redacted
			continue
		}

		switch t := v.(type) {
		case map[string]any:
			mask(t, fieldNames)
		case []any:
			for i, item := range t {
				if subData, ok := item.(map[string]any); ok {
					mask(subData, fieldNames)
					t[i] = subData
				}
			}
		}
	}
}
