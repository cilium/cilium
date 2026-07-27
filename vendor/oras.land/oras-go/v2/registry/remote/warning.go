/*
Copyright The ORAS Authors.
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

package remote

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// headerWarning is the "Warning" header.
	// Reference: https://www.rfc-editor.org/rfc/rfc7234#section-5.5
	headerWarning = "Warning"

	// warnCode299 is the 299 warn-code.
	// Reference: https://www.rfc-editor.org/rfc/rfc7234#section-5.5
	warnCode299 = 299

	// warnAgentUnknown represents an unknown warn-agent.
	// Reference: https://www.rfc-editor.org/rfc/rfc7234#section-5.5
	warnAgentUnknown = "-"
)

// errUnexpectedWarningFormat is returned by parseWarningHeader when
// an unexpected warning format is encountered.
var errUnexpectedWarningFormat = errors.New("unexpected warning format")

// WarningValue represents the value of the Warning header.
//
// References:
//   - https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#warnings
//   - https://www.rfc-editor.org/rfc/rfc7234#section-5.5
type WarningValue struct {
	// Code is the warn-code.
	Code int
	// Agent is the warn-agent.
	Agent string
	// Text is the warn-text.
	Text string
}

// Warning contains the value of the warning header and may contain
// other information related to the warning.
//
// References:
//   - https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#warnings
//   - https://www.rfc-editor.org/rfc/rfc7234#section-5.5
type Warning struct {
	// WarningValue is the value of the warning header.
	WarningValue
}

// parseWarningHeader parses the warning header into WarningValue.
func parseWarningHeader(header string) (WarningValue, error) {
	if len(header) < 9 || !strings.HasPrefix(header, `299 - "`) || !strings.HasSuffix(header, `"`) {
		// minimum header value: `299 - "x"`
		return WarningValue{}, fmt.Errorf("%s: %w", header, errUnexpectedWarningFormat)
	}

	// validate text only as code and agent are fixed
	quotedText := header[6:] // behind `299 - `, quoted by "
	text, err := strconv.Unquote(quotedText)
	if err != nil {
		return WarningValue{}, fmt.Errorf("%s: unexpected text: %w: %v", header, errUnexpectedWarningFormat, err)
	}

	return WarningValue{
		Code:  warnCode299,
		Agent: warnAgentUnknown,
		Text:  text,
	}, nil
}

// handleWarningHeaders parses the warning headers and handles the parsed
// warnings using handleWarning.
func handleWarningHeaders(headers []string, handleWarning func(Warning)) {
	for _, h := range headers {
		if value, err := parseWarningHeader(h); err == nil {
			// ignore warnings in unexpected formats
			handleWarning(Warning{
				WarningValue: value,
			})
		}
	}
}
