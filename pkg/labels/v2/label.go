// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"unique"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Label is a unique source, key and value tuple.
type Label unique.Handle[labelRep]

// NewLabel returns a new label. Labels created with the same
// source, key and value will share a single allocation.
func NewLabel(key, value, source string) Label {
	return NewCIDRLabel(key, value, source, nil)
}

func NewCIDRLabel(key, value, source string, cidr *netip.Prefix) Label {
	skv := source + ":" + key
	if value != "" {
		skv += "=" + value
	}
	return Label(unique.Make(labelRep{
		skv:  skv,
		kpos: uint16(len(source) + 1),
		vpos: uint16(len(source) + 1 + len(key) + 1),
		cidr: cidr,
	}))
}

func (l Label) String() string {
	return l.rep().skv
}

func (l Label) Source() string { return l.rep().source() }
func (l Label) Key() string    { return l.rep().key() }
func (l Label) Value() string  { return l.rep().value() }

func (l Label) Equal(other Label) bool {
	return l == other
}

type jsonLabel struct {
	Key    string `json:"key"`
	Value  string `json:"value,omitempty"`
	Source string `json:"source"`
}

func (l Label) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonLabel{
		l.Key(), l.Value(), l.Source(),
	})
}

func (l *Label) UnmarshalJSON(b []byte) error {
	var jl jsonLabel
	err := json.Unmarshal(b, &jl)
	if err != nil {
		// If parsing of the full representation failed then try the short
		// form in the format:
		//
		// [SOURCE:]KEY[=VALUE]
		var aux string

		if err := json.Unmarshal(b, &aux); err != nil {
			return fmt.Errorf("decode of Label as string failed: %w", err)
		}

		if aux == "" {
			return fmt.Errorf("invalid Label: Failed to parse %s as a string", b)
		}

		*l = ParseLabel(aux)
		return nil
	} else {
		if jl.Key == "" {
			return fmt.Errorf("invalid Label: '%s' does not contain label key", b)
		}

		*l = NewLabel(jl.Key, jl.Value, jl.Source)
	}

	if jl.Source == LabelSourceCIDR {
		c, err := LabelToPrefix(l.Key())
		if err == nil {
			*l = NewCIDRLabel(jl.Key, jl.Value, jl.Source, &c)
		} else {
			return fmt.Errorf("failed to parse CIDR label: invalid prefix: %w", err)
		}
	} else {
		*l = NewLabel(jl.Key, jl.Value, jl.Source)
	}

	return nil
}

func (l Label) rep() labelRep {
	return (unique.Handle[labelRep])(l).Value()
}

// labelRep is the internal unique'd representation for a label.
type labelRep struct {
	// skv is the concatenated source, key and value. It is the direct
	// string representation for the label: "Source:Key=Value".
	// We're optimizing for low runtime memory usage and number of allocated
	// objects by concatenating them.
	skv string

	// kpos is the position of the key in skv
	kpos uint16

	// vpos is the position of the value in skv
	vpos uint16

	// optimization for CIDR prefixes
	cidr *netip.Prefix
}

func (rep labelRep) source() string {
	return rep.skv[:rep.kpos-1]
}
func (rep labelRep) key() string {
	return rep.skv[rep.kpos : rep.vpos-1]
}
func (rep labelRep) value() string {
	if int(rep.vpos) >= len(rep.skv) {
		return ""
	}
	return rep.skv[rep.vpos:]
}

// ParseLabel returns the label representation of the given string. The str should be
// in the form of Source:Key=Value or Source:Key if Value is empty. It also parses short
// forms, for example: $host will be Label{Key: "host", Source: "reserved", Value: ""}.
func ParseLabel(str string) Label {
	return parseLabel(str, ':')
}

// ParseSource returns the parsed source of the given str. It also returns the next piece
// of text that is after the source.
// Example:
//
//	src, next := ParseSource("foo:bar==value")
//
// Println(src) // foo
// Println(next) // bar==value
// For Cilium format 'delim' must be passed in as ':'
// For k8s format 'delim' must be passed in as '.'
func ParseSource(str string, delim byte) (src, next string) {
	if str == "" {
		return "", ""
	}
	if str[0] == '$' {
		return LabelSourceReserved, str[1:]
	}
	i := strings.IndexByte(str, delim)
	if i < 0 {
		if delim != '.' && strings.HasPrefix(str, LabelSourceReservedKeyPrefix) {
			return LabelSourceReserved, strings.TrimPrefix(str, LabelSourceReservedKeyPrefix)
		}
		return "", str
	}
	return str[:i], str[i+1:]
}

// parseLabel returns the label representation of the given string by value.
// For Cilium format 'delim' must be passed in as ':'
// For k8s format 'delim' must be passed in as '.'
func parseLabel(str string, delim byte) Label {
	src, next := ParseSource(str, delim)
	if src == "" {
		src = LabelSourceUnspec
	}
	var key, value string

	i := strings.IndexByte(next, '=')
	if i < 0 {
		key = next
	} else {
		if i == 0 && src == LabelSourceReserved {
			key = next[i+1:]
		} else {
			key = next[:i]
			value = next[i+1:]
		}
	}

	if src == LabelSourceCIDR {
		if value != "" {
			// FIXME: figure out what to do with these loggings. Return errors instead? Why is this
			// logging in the first place and continuing?
			logrus.WithField(logfields.Label, src+":"+key+"="+value).Error("Invalid CIDR label: labels with source cidr cannot have values.")
		} else {
			c, err := LabelToPrefix(key)
			if err != nil {
				logrus.WithField(logfields.Label, str).WithError(err).Error("Failed to parse CIDR label: invalid prefix.")
			} else {
				return NewCIDRLabel(key, value, src, &c)
			}
		}
	}

	return NewLabel(key, value, src)
}

// ParseSelectLabel returns a selecting label representation of the given
// string. Unlike ParseLabel, if source is unspecified, the source defaults to
// LabelSourceAny
func ParseSelectLabel(str string) Label {
	return ParseSelectLabelWithDelim(str, ':')
}

// ParseSelectLabelWithDelim returns a selecting label representation of the given
// string by value.
// For Cilium format 'delim' must be passed in as ':'
// For k8s format 'delim' must be passed in as '.'
func ParseSelectLabelWithDelim(str string, delim byte) Label {
	lbl := parseLabel(str, delim)
	if lbl.Source() == LabelSourceUnspec {
		return NewLabel(lbl.Key(), lbl.Value(), LabelSourceAny)
	}
	return lbl
}
