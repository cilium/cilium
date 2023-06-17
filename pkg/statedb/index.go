// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"fmt"
	"net"
	"reflect"
	"strings"
)

type IPIndexer struct {
	Field string
}

var ipType = reflect.TypeOf(net.IP{})

func (ii *IPIndexer) FromObject(obj interface{}) (bool, []byte, error) {
	v := reflect.ValueOf(obj)
	v = reflect.Indirect(v) // Dereference the pointer if any

	fv := v.FieldByName(ii.Field)
	if !fv.IsValid() {
		return false, nil,
			fmt.Errorf("field '%s' for %#v is invalid", ii.Field, obj)
	}

	var ip net.IP

	if fv.Type() == ipType {
		ip = fv.Interface().(net.IP)
	} else {
		ip = net.ParseIP(fv.String())
	}

	return true, []byte(ip), nil
}

func (ii *IPIndexer) FromArgs(args ...interface{}) ([]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("must provide only a single argument")
	}
	switch arg := args[0].(type) {
	case string:
		return net.ParseIP(arg), nil
	case net.IP:
		return arg, nil
	case []byte:
		if len(arg) != net.IPv4len || len(arg) != net.IPv6len {
			return nil, fmt.Errorf("byte slice must represent an IPv4 or IPv6 address")
		}
		return arg, nil
	default:
		return nil,
			fmt.Errorf("argument must be a net.IP, string or byte slice: %#v", args[0])
	}
}

func (ii *IPIndexer) PrefixFromArgs(args ...interface{}) ([]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("must provide only a single argument")
	}
	switch arg := args[0].(type) {
	case string:
		return net.ParseIP(arg), nil
	case net.IP:
		return arg, nil
	case []byte:
		return arg, nil
	default:
		return nil,
			fmt.Errorf("argument must be a net.IP, string or byte slice: %#v", args[0])
	}
}

// StringerSliceFieldIndex builds an index from a field on an object that is a
// slice of objects that implement fmt.Stringer.
// Each value within the string slice can be used for lookup.
type StringerSliceFieldIndex struct {
	Field     string
	Lowercase bool
}

var stringerType = reflect.TypeOf((*fmt.Stringer)(nil)).Elem()

func (s *StringerSliceFieldIndex) FromObject(obj interface{}) (bool, [][]byte, error) {
	v := reflect.ValueOf(obj)
	v = reflect.Indirect(v) // Dereference the pointer if any

	fv := v.FieldByName(s.Field)
	if !fv.IsValid() {
		return false, nil,
			fmt.Errorf("field '%s' for %#v is invalid", s.Field, obj)
	}

	if fv.Kind() != reflect.Slice || !fv.Type().Elem().Implements(stringerType) {
		return false, nil, fmt.Errorf("field '%s' is not a fmt.Stringer slice", s.Field)
	}

	length := fv.Len()
	vals := make([][]byte, 0, length)
	for i := 0; i < fv.Len(); i++ {
		val := fv.Index(i).Interface().(fmt.Stringer).String()
		if val == "" {
			continue
		}

		if s.Lowercase {
			val = strings.ToLower(val)
		}

		// Add the null character as a terminator
		val += "\x00"
		vals = append(vals, []byte(val))
	}
	if len(vals) == 0 {
		return false, nil, nil
	}
	return true, vals, nil
}

func (s *StringerSliceFieldIndex) FromArgs(args ...interface{}) ([]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("must provide only a single argument")
	}
	stringer, ok := args[0].(fmt.Stringer)
	if !ok {
		return nil, fmt.Errorf("argument must be a fmt.Stringer: %#v", args[0])
	}
	arg := stringer.String()
	if s.Lowercase {
		arg = strings.ToLower(arg)
	}
	// Add the null character as a terminator
	arg += "\x00"
	return []byte(arg), nil
}

func (s *StringerSliceFieldIndex) PrefixFromArgs(args ...interface{}) ([]byte, error) {
	val, err := s.FromArgs(args...)
	if err != nil {
		return nil, err
	}

	// Strip the null terminator, the rest is a prefix
	n := len(val)
	if n > 0 {
		return val[:n-1], nil
	}
	return val, nil
}
