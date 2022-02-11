// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of Cilium

package command

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"

	"github.com/spf13/cast"
	"github.com/spf13/viper"
)

var keyValueRegex = regexp.MustCompile(`([\w-:./]+=[\w-:./]+,)*([\w-:./]+=[\w-:./]+)$`)

// GetStringMapString contains one enhancement to support k1=v2,k2=v2 compared to original
// implementation of GetStringMapString function
// Related upstream issue https://github.com/spf13/viper/issues/911
func GetStringMapString(vp *viper.Viper, key string) map[string]string {
	v, _ := GetStringMapStringE(vp, key)
	return v
}

// GetStringMapStringE is same as GetStringMapString, but with error
func GetStringMapStringE(vp *viper.Viper, key string) (map[string]string, error) {
	data := vp.Get(key)
	if data == nil {
		return map[string]string{}, nil
	}
	v, err := cast.ToStringMapStringE(data)
	if err != nil {
		var syntaxErr *json.SyntaxError
		if !errors.As(err, &syntaxErr) {
			return v, err
		}

		switch s := data.(type) {
		case string:
			if len(s) == 0 {
				return map[string]string{}, nil
			}

			// if the input is starting with either '{' or '[', just preserve original json parsing error.
			firstIndex := strings.IndexFunc(s, func(r rune) bool {
				return !unicode.IsSpace(r)
			})
			if firstIndex != -1 && (s[firstIndex] == '{' || s[firstIndex] == '[') {
				return v, err
			}

			if !isValidKeyValuePair(s) {
				return map[string]string{}, fmt.Errorf("'%s' is not formatted as key=value,key1=value1", s)
			}

			var v = map[string]string{}
			kvs := strings.Split(s, ",")
			for _, kv := range kvs {
				temp := strings.Split(kv, "=")
				if len(temp) != 2 {
					return map[string]string{}, fmt.Errorf("'%s' is not formatted as key=value,key1=value1", s)
				}
				v[temp[0]] = temp[1]
			}
			return v, nil
		}
	}
	return v, nil
}

// isValidKeyValuePair returns true if the input is following key1=value1,key2=value2,...,keyN=valueN format.
func isValidKeyValuePair(str string) bool {
	if len(str) == 0 {
		return true
	}
	return len(keyValueRegex.ReplaceAllString(str, "")) == 0
}
