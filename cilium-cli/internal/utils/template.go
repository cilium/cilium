package utils

import (
	"bytes"
	"text/template"
)

// RenderTemplate executes temp with data and returns the result
func RenderTemplate(temp string, data any) (string, error) {
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
