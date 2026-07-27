// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"encoding/json"
	"io"
)

// Encoder provides encoding capabilities for arbitrary data.
type Encoder interface {
	Encode(v any) error
}

// NewEncoderFunc constructs a new Encoder.
type NewEncoderFunc func(writer io.Writer) (Encoder, error)

// JsonEncoder is a NewEncoderFunc that returns a JSON encoder.
func JsonEncoder(writer io.Writer) (Encoder, error) {
	return json.NewEncoder(writer), nil
}
