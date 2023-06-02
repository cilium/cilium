// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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

const (
	comma = ','
	equal = '='
)

var keyValueRegex = regexp.MustCompile(`([\w-:;./@]+=([\w-:;,./@][\w-:;,./@ ]*[\w-:;,./@])?[\w-:;,./@]*,)*([\w-:;./@]+=([\w-:;,./@][\w-:;,./@ ]*)?[\w-:;./@]+)$`)

// GetStringMapString contains one enhancement to support k1=v2,k2=v2 compared to original
// implementation of GetStringMapString function
// Related upstream issue https://github.com/spf13/viper/issues/911
func GetStringMapString(vp *viper.Viper, key string) map[string]string {
	v, _ := GetStringMapStringE(vp, key)
	return v
}

// GetStringMapStringE is same as GetStringMapString, but with error
func GetStringMapStringE(vp *viper.Viper, key string) (map[string]string, error) {
	return ToStringMapStringE(vp.Get(key))
}

// ToStringMapStringE casts an interface to a map[string]string type. The underlying
// interface type might be a map or string. In the latter case, it is attempted to be
// json decoded, falling back to the k1=v2,k2=v2 format in case it doesn't look like json.
func ToStringMapStringE(data interface{}) (map[string]string, error) {
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
			kvs := splitKeyValue(s, comma, equal)
			for _, kv := range kvs {
				temp := strings.Split(kv, string(equal))
				if len(temp) != 2 {
					return map[string]string{}, fmt.Errorf("'%s' in '%s' is not formatted as key=value,key1=value1", kv, s)
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

// splitKeyValue is similar to strings.Split, but looks ahead to make sure
// that sep character is allowed in value component of key-value pair.
//
// Example: with the input "c6a.2xlarge=4,15,15,m4.xlarge=2,4,8",
// - strings.Split function will return []string{"c6a.2xlarge=4", "15", "15", "m4.xlarge=2", "4", "8"}.
// - splitKeyValue function will return []string{"c6a.2xlarge=4,15,15", "m4.xlarge=2,4,8"} instead.
func splitKeyValue(str string, sep rune, keyValueSep rune) []string {
	var sepIndexes, kvValueSepIndexes []int
	// find all indexes of separator character
	for i := 0; i < len(str); i++ {
		switch int32(str[i]) {
		case sep:
			sepIndexes = append(sepIndexes, i)
		case keyValueSep:
			kvValueSepIndexes = append(kvValueSepIndexes, i)
		}
	}

	// there's only a single key-value if there are no separators ("key=value")
	// or a single key-value separator ("key=option1:value1,option2:value2")
	if len(sepIndexes) == 0 || len(kvValueSepIndexes) == 1 {
		return []string{str}
	}

	if len(sepIndexes) == 1 {
		index := sepIndexes[0]
		return []string{str[:index], str[index+1:]}
	}

	var res []string
	var start = 0
	for i := 0; i < len(sepIndexes); i++ {
		last := len(str)
		if i < len(sepIndexes)-1 {
			last = sepIndexes[i+1]
		}
		if strings.ContainsRune(str[sepIndexes[i]:last], keyValueSep) {
			res = append(res, str[start:sepIndexes[i]])
			start = sepIndexes[i] + 1
		}
	}
	// append the remaining for last sep index
	res = append(res, str[start:])
	return res
}
