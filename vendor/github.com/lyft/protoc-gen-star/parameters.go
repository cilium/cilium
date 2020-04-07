package pgs

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const outputPathKey = "output_path"

// Parameters provides a convenience for accessing and modifying the parameters
// passed into the protoc-gen-star plugin.
type Parameters map[string]string

// ParseParameters converts the raw params string provided by protoc into a
// representative mapping.
func ParseParameters(p string) (params Parameters) {
	parts := strings.Split(p, ",")
	params = make(map[string]string, len(parts))

	for _, p = range parts {
		if i := strings.Index(p, "="); i < 0 {
			params[p] = ""
		} else {
			params[p[:i]] = p[i+1:]
		}
	}

	return
}

// Clone creates an independent copy of Parameters p.
func (p Parameters) Clone() Parameters {
	out := make(Parameters, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}

// OutputPath returns the protoc-gen-star special parameter. If not set in the
// execution of protoc, "." is returned, indicating that output is relative to
// the (unknown) output location for sub-plugins or the directory where protoc
// is executed for a Module. Setting "output_path" during the protoc execution
// ensures that Modules can know absolutely where to generate code.
func (p Parameters) OutputPath() string { return p.StrDefault(outputPathKey, ".") }

// SetOutputPath sets the protoc-gen-star OutputPath parameter. This is useful
// for overriding the behavior of the ImportPath at runtime.
func (p Parameters) SetOutputPath(path string) { p.SetStr(outputPathKey, path) }

// String satisfies the string.Stringer interface. This method returns p in the
// format it is provided to the protoc execution. Output of this function is
// always stable; parameters are sorted before the string is emitted.
func (p Parameters) String() string {
	parts := make([]string, 0, len(p))

	for k, v := range p {
		if v == "" {
			parts = append(parts, k)
		} else {
			parts = append(parts, fmt.Sprintf("%s=%s", k, v))
		}
	}

	sort.Strings(parts)

	return strings.Join(parts, ",")
}

// Str returns the parameter with name, returning an empty string if it is not
// set.
func (p Parameters) Str(name string) string { return p.StrDefault(name, "") }

// StrDefault returns the parameter with name, or if it is unset, returns the
// def default value.
func (p Parameters) StrDefault(name string, def string) string {
	if s, ok := p[name]; ok {
		return s
	}

	return def
}

// SetStr sets the parameter name to s.
func (p Parameters) SetStr(name string, s string) { p[name] = s }

// Int returns the parameter with name, returning zero if it is not set. An
// error is returned if the value cannot be parsed as an int.
func (p Parameters) Int(name string) (int, error) { return p.IntDefault(name, 0) }

// IntDefault returns the parameter with name, or if it is unset, returns the
// def default value. An error is returned if the value cannot be parsed as an
// int.
func (p Parameters) IntDefault(name string, def int) (int, error) {
	if s, ok := p[name]; ok {
		return strconv.Atoi(s)
	}
	return def, nil
}

// SetInt sets the parameter name to i.
func (p Parameters) SetInt(name string, i int) { p[name] = strconv.Itoa(i) }

// Uint returns the parameter with name, returning zero if it is not set. An
// error is returned if the value cannot be parsed as a base-10 uint.
func (p Parameters) Uint(name string) (uint, error) { return p.UintDefault(name, 0) }

// UintDefault returns the parameter with name, or if it is unset, returns the
// def default value. An error is returned if the value cannot be parsed as a
// base-10 uint.
func (p Parameters) UintDefault(name string, def uint) (uint, error) {
	if s, ok := p[name]; ok {
		ui, err := strconv.ParseUint(s, 10, strconv.IntSize)
		return uint(ui), err
	}
	return def, nil
}

// SetUint sets the parameter name to ui.
func (p Parameters) SetUint(name string, ui uint) { p[name] = strconv.FormatUint(uint64(ui), 10) }

// Float returns the parameter with name, returning zero if it is
// not set. An error is returned if the value cannot be parsed as a float64
func (p Parameters) Float(name string) (float64, error) { return p.FloatDefault(name, 0) }

// FloatDefault returns the parameter with name, or if it is unset, returns the
// def default value. An error is returned if the value cannot be parsed as a
// float64.
func (p Parameters) FloatDefault(name string, def float64) (float64, error) {
	if s, ok := p[name]; ok {
		return strconv.ParseFloat(s, 64)
	}
	return def, nil
}

// SetFloat sets the parameter name to f.
func (p Parameters) SetFloat(name string, f float64) { p[name] = strconv.FormatFloat(f, 'g', -1, 64) }

// Bool returns the parameter with name, returning false if it is not set. An
// error is returned if the value cannot be parsed as a boolean. Empty values
// are considered true.
func (p Parameters) Bool(name string) (bool, error) { return p.BoolDefault(name, false) }

// BoolDefault returns the parameter with name, or if it is unset, returns the
// def default value. An error is returned if the value cannot be parsed as a
// boolean. Empty values are considered true.
func (p Parameters) BoolDefault(name string, def bool) (bool, error) {
	if s, ok := p[name]; ok {
		if strings.TrimSpace(s) == "" {
			return true, nil
		}
		return strconv.ParseBool(s)
	}

	return def, nil
}

// SetBool sets the parameter name to b.
func (p Parameters) SetBool(name string, b bool) { p[name] = strconv.FormatBool(b) }

// Duration returns the parameter with name, returning zero if it is not set.
// An error is returned if the value cannot be parsed as a time.Duration.
func (p Parameters) Duration(name string) (time.Duration, error) { return p.DurationDefault(name, 0) }

// DurationDefault returns the parameter with name, or if it is unset, returns
// the def default value. An error is returned if the value cannot be parsed as
// a time.Duration.
func (p Parameters) DurationDefault(name string, def time.Duration) (time.Duration, error) {
	if s, ok := p[name]; ok {
		return time.ParseDuration(s)
	}
	return def, nil
}

// SetDuration sets the parameter name to d.
func (p Parameters) SetDuration(name string, d time.Duration) { p[name] = d.String() }
