// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package template

import (
	"bytes"
	"html/template"
	"net/netip"
	"strings"
)

// Render executes temp template with data and returns the result
func Render(temp string, data any) (string, error) {
	fns := template.FuncMap{
		"trimSuffix": func(in, suffix string) string { return strings.TrimSuffix(in, suffix) },
		"ipToCIDR": func(ipString string) string {
			if ip, err := netip.ParseAddr(ipString); err == nil && ip.Is6() {
				return ipString + "/128" // IPv6 address
			} else {
				return ipString + "/32" // otherwise assume IPv4
			}
		},
	}

	tm, err := template.New("template").Funcs(fns).Parse(temp)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBuffer(nil)
	if err := tm.Execute(buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}
