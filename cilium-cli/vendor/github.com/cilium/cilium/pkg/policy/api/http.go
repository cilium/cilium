// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2017 Authors of Cilium

package api

import (
	"fmt"
	"regexp"
)

// MismatchAction specifies what to do when there is no header match
// Empty string is the default for making the rule to fail the match.
// Otherwise the rule is still considered as matching, but the mismatches
// are logged in the access log.
type MismatchAction string

const (
	MismatchActionLog     MismatchAction = "LOG"     // Keep checking other matches
	MismatchActionAdd     MismatchAction = "ADD"     // Add the missing value to a possibly multi-valued header
	MismatchActionDelete  MismatchAction = "DELETE"  // Remove the whole mismatching header
	MismatchActionReplace MismatchAction = "REPLACE" // Replace (of add if missing) the header
)

// HeaderMatch extends the HeaderValue for matching requirement of a
// named header field against an immediate string, a secret value, or
// a regex.  If none of the optional fields is present, then the
// header value is not matched, only presence of the header is enough.
type HeaderMatch struct {
	// Mismatch identifies what to do in case there is no match. The default is
	// to drop the request. Otherwise the overall rule is still considered as
	// matching, but the mismatches are logged in the access log.
	//
	// +kubebuilder:validation:Enum=LOG;ADD;DELETE;REPLACE
	// +kubebuilder:validation:Optional
	Mismatch MismatchAction `json:"mismatch,omitempty"`

	// Name identifies the header.
	Name string `json:"name"`

	// Secret refers to a secret that contains the value to be matched against.
	// The secret must only contain one entry. If the referred secret does not
	// exist, and there is no "Value" specified, the match will fail.
	//
	// +kubebuilder:validation:Optional
	Secret *Secret `json:"secret,omitempty"`

	// Value matches the exact value of the header. Can be specified either
	// alone or together with "Secret"; will be used as the header value if the
	// secret can not be found in the latter case.
	//
	// +kubebuilder:validation:Optional
	Value string `json:"value,omitempty"`
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
	// +kubebuilder:validation:Optional
	Path string `json:"path,omitempty"`

	// Method is an extended POSIX regex matched against the method of a
	// request, e.g. "GET", "POST", "PUT", "PATCH", "DELETE", ...
	//
	// If omitted or empty, all methods are allowed.
	//
	// +kubebuilder:validation:Optional
	Method string `json:"method,omitempty"`

	// Host is an extended POSIX regex matched against the host header of a
	// request, e.g. "foo.com"
	//
	// If omitted or empty, the value of the host header is ignored.
	//
	// +kubebuilder:validation:Format=idn-hostname
	// +kubebuilder:validation:Optional
	Host string `json:"host,omitempty"`

	// Headers is a list of HTTP headers which must be present in the
	// request. If omitted or empty, requests are allowed regardless of
	// headers present.
	//
	// +kubebuilder:validation:Optional
	Headers []string `json:"headers,omitempty"`

	// HeaderMatches is a list of HTTP headers which must be
	// present and match against the given values. Mismatch field can be used
	// to specify what to do when there is no match.
	//
	// +kubebuilder:validation:Optional
	HeaderMatches []*HeaderMatch `json:"headerMatches,omitempty"`
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

	// But HeaderMatches are
	for _, m := range h.HeaderMatches {
		if m.Name == "" {
			return fmt.Errorf("Header name missing")
		}
		if m.Mismatch != "" &&
			m.Mismatch != MismatchActionLog && m.Mismatch != MismatchActionAdd &&
			m.Mismatch != MismatchActionDelete && m.Mismatch != MismatchActionReplace {
			return fmt.Errorf("Invalid header action: %s", m.Mismatch)
		}
		if m.Secret != nil && m.Secret.Name == "" {
			return fmt.Errorf("Secret name missing")
		}
	}

	return nil
}
