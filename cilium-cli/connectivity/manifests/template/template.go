// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package template

import (
	"bytes"
	"html/template"
)

// Render executes temp template with data and returns the result
func Render(temp string, data any) (string, error) {
	tm, err := template.New("template").Parse(temp)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBuffer(nil)
	if err := tm.Execute(buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}
