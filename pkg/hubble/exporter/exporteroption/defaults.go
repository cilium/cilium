// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporteroption

import (
	"encoding/json"
	"io"
)

// Default specifies default values for Hubble exporter options.
var Default = Options{
	Path:           "", // An empty string disables Hubble export.
	MaxSizeMB:      10,
	MaxBackups:     5,
	Compress:       false,
	NewEncoderFunc: JsonEncoder,
}

// JsonEncoder is a NewEncoderFunc that returns a JSON encoder.
func JsonEncoder(writer io.Writer) (Encoder, error) {
	return json.NewEncoder(writer), nil
}
