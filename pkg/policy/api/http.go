// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import "regexp"

// HeaderValue specifies a value requirement of a named header
// field. The value can be an inline string or a k8s secret value.  If
// none of the optional fields is present, then the value is
// considered to be an empty string.
type HeaderValue struct {
	// Name identifies the header
	Name string `json:"name,omitempty"`

	// Secret refers to a k8s secret that contains the value to be matched against.
	// The secret must only contain one entry.
	// If the referred secret does not exist, the match will fail.
	//
	// +optional
	Secret *K8sSecret `json:"secret,omitempty"`

	// Value matches the exact value of the header.
	//
	// +optional
	Value string `json:"value,omitempty"`
}

// HeaderMatch extends the HeaderValue for matching requirement of a
// named header field against an immediate string, a secret value, or
// a regex.  If none of the optional fields is present, then the
// header value is not matched, only presence of the header is enough.
type HeaderMatch struct {
	HeaderValue

	// Regex specifies a regex for the GoogleRE2 engine that must match the whole value.
	//
	// +optional
	Regex string `json:"regex,omitempty"`

	// RegexLimit controls the maximum generated regex program
	// complexity. If the limit is exceeded the regex fails to
	// compile and the policy setup fails. Defaults to the Envoy
	// default of 100.
	RegexLimit uint32 `json:"regexLimit,omitempty"`
}

// PortRuleHTTP is a list of HTTP protocol constraints. All fields are
// optional, if all fields are empty or missing, the rule does not have any
// effect.
//
// All fields of this type are extended POSIX regex as defined by IEEE Std
// 1003.1, (i.e this follows the egrep/unix syntax, not the perl syntax)
// matched against the path of an incoming request. Currently it can contain
// characters disallowed from the conventional "path" part of a URL as defined
// by RFC 3986.
type PortRuleHTTP struct {
	// Path is an extended POSIX regex matched against the path of a
	// request. Currently it can contain characters disallowed from the
	// conventional "path" part of a URL as defined by RFC 3986.
	//
	// If omitted or empty, all paths are all allowed.
	//
	// +optional
	Path string `json:"path,omitempty"`

	// Method is an extended POSIX regex matched against the method of a
	// request, e.g. "GET", "POST", "PUT", "PATCH", "DELETE", ...
	//
	// If omitted or empty, all methods are allowed.
	//
	// +optional
	Method string `json:"method,omitempty"`

	// Host is an extended POSIX regex matched against the host header of a
	// request, e.g. "foo.com"
	//
	// If omitted or empty, the value of the host header is ignored.
	//
	// +optional
	Host string `json:"host,omitempty"`

	// Headers is a list of HTTP headers which must be present in the
	// request. If omitted or empty, requests are allowed regardless of
	// headers present.
	//
	// Deprecated: Use MatchHeaders instead.
	//
	// +optional
	Headers []string `json:"headers,omitempty"`

	// MatchHeaders is a list of HTTP headers which must be
	// present and match against the given k8s secret values.
	//
	// +optional
	MatchHeaders []*HeaderMatch `json:"matchHeaders,omitempty"`

	// ImposeHeaders is a list of HTTP headers which will be
	// placed into request headers, if all the other match
	// requirements are met, and if not already present with the
	// given value. A missing or incorrect value will not cause
	// the request to be dropped, but access log messages will
	// note if a header needed to be imposed.
	//
	// +optional
	ImposeHeaders []*HeaderValue `json:"imposeHeaders,omitempty"`
}

// Sanitize sanitizes HTTP rules. It ensures that the path and method fields
// are valid regular expressions. Note that the proxy may support a wider-range
// of regular expressions (e.g. that specified by ECMAScript), so this function
// may return some false positives. If the rule is invalid, returns an error.
func (h *PortRuleHTTP) Sanitize() error {

	if h.Path != "" {
		_, err := regexp.Compile(h.Path)
		if err != nil {
			return err
		}
	}

	if h.Method != "" {
		_, err := regexp.Compile(h.Method)
		if err != nil {
			return err
		}
	}

	// Headers are not sanitized.
	return nil
}
