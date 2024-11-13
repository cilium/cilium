// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporteroption

import (
	"encoding/json"
	"io"
)

// Default specifies default values for Hubble exporter options.
var Default = Options{
	NewWriterFunc:  StdoutNoOpWriter,
	NewEncoderFunc: JsonEncoder,
}

// JsonEncoder is a NewEncoderFunc that returns a JSON encoder.
func JsonEncoder(writer io.Writer) (Encoder, error) {
	return json.NewEncoder(writer), nil
}
