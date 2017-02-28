package toml

// Tools to convert a TomlTree to different representations

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// encodes a string to a TOML-compliant string value
func encodeTomlString(value string) string {
	result := ""
	for _, rr := range value {
		intRr := uint16(rr)
		switch rr {
		case '\b':
			result += "\\b"
		case '\t':
			result += "\\t"
		case '\n':
			result += "\\n"
		case '\f':
			result += "\\f"
		case '\r':
			result += "\\r"
		case '"':
			result += "\\\""
		case '\\':
			result += "\\\\"
		default:
			if intRr < 0x001F {
				result += fmt.Sprintf("\\u%0.4X", intRr)
			} else {
				result += string(rr)
			}
		}
	}
	return result
}

// Value print support function for ToString()
// Outputs the TOML compliant string representation of a value
func toTomlValue(item interface{}, indent int) string {
	tab := strings.Repeat(" ", indent)
	switch value := item.(type) {
	case int:
		return tab + strconv.FormatInt(int64(value), 10)
	case int8:
		return tab + strconv.FormatInt(int64(value), 10)
	case int16:
		return tab + strconv.FormatInt(int64(value), 10)
	case int32:
		return tab + strconv.FormatInt(int64(value), 10)
	case int64:
		return tab + strconv.FormatInt(value, 10)
	case uint:
		return tab + strconv.FormatUint(uint64(value), 10)
	case uint8:
		return tab + strconv.FormatUint(uint64(value), 10)
	case uint16:
		return tab + strconv.FormatUint(uint64(value), 10)
	case uint32:
		return tab + strconv.FormatUint(uint64(value), 10)
	case uint64:
		return tab + strconv.FormatUint(value, 10)
	case float32:
		return tab + strconv.FormatFloat(float64(value), 'f', -1, 32)
	case float64:
		return tab + strconv.FormatFloat(value, 'f', -1, 64)
	case string:
		return tab + "\"" + encodeTomlString(value) + "\""
	case bool:
		if value {
			return "true"
		}
		return "false"
	case time.Time:
		return tab + value.Format(time.RFC3339)
	case []interface{}:
		values := []string{}
		for _, item := range value {
			values = append(values, toTomlValue(item, 0))
		}
		return "[" + strings.Join(values, ",") + "]"
	case nil:
		return ""
	default:
		panic(fmt.Errorf("unsupported value type %T: %v", value, value))
	}
}

// Recursive support function for ToString()
// Outputs a tree, using the provided keyspace to prefix table names
func (t *TomlTree) toToml(indent, keyspace string) string {
	resultChunks := []string{}
	for k, v := range t.values {
		// figure out the keyspace
		combinedKey := k
		if keyspace != "" {
			combinedKey = keyspace + "." + combinedKey
		}
		resultChunk := ""
		// output based on type
		switch node := v.(type) {
		case []*TomlTree:
			for _, item := range node {
				if len(item.Keys()) > 0 {
					resultChunk += fmt.Sprintf("\n%s[[%s]]\n", indent, combinedKey)
				}
				resultChunk += item.toToml(indent+"  ", combinedKey)
			}
			resultChunks = append(resultChunks, resultChunk)
		case *TomlTree:
			if len(node.Keys()) > 0 {
				resultChunk += fmt.Sprintf("\n%s[%s]\n", indent, combinedKey)
			}
			resultChunk += node.toToml(indent+"  ", combinedKey)
			resultChunks = append(resultChunks, resultChunk)
		case map[string]interface{}:
			sub := TreeFromMap(node)

			if len(sub.Keys()) > 0 {
				resultChunk += fmt.Sprintf("\n%s[%s]\n", indent, combinedKey)
			}
			resultChunk += sub.toToml(indent+"  ", combinedKey)
			resultChunks = append(resultChunks, resultChunk)
		case map[string]string:
			sub := TreeFromMap(convertMapStringString(node))

			if len(sub.Keys()) > 0 {
				resultChunk += fmt.Sprintf("\n%s[%s]\n", indent, combinedKey)
			}
			resultChunk += sub.toToml(indent+"  ", combinedKey)
			resultChunks = append(resultChunks, resultChunk)
		case map[interface{}]interface{}:
			sub := TreeFromMap(convertMapInterfaceInterface(node))

			if len(sub.Keys()) > 0 {
				resultChunk += fmt.Sprintf("\n%s[%s]\n", indent, combinedKey)
			}
			resultChunk += sub.toToml(indent+"  ", combinedKey)
			resultChunks = append(resultChunks, resultChunk)
		case *tomlValue:
			resultChunk = fmt.Sprintf("%s%s = %s\n", indent, k, toTomlValue(node.value, 0))
			resultChunks = append([]string{resultChunk}, resultChunks...)
		default:
			resultChunk = fmt.Sprintf("%s%s = %s\n", indent, k, toTomlValue(v, 0))
			resultChunks = append([]string{resultChunk}, resultChunks...)
		}

	}
	return strings.Join(resultChunks, "")
}

// Same as ToToml(), but does not panic and returns an error
func (t *TomlTree) toTomlSafe(indent, keyspace string) (result string, err error) {
	defer func() {
		if r := recover(); r != nil {
			result = ""
			switch x := r.(type) {
			case error:
				err = x
			default:
				err = fmt.Errorf("unknown panic: %s", r)
			}
		}
	}()
	result = t.toToml(indent, keyspace)
	return
}

func convertMapStringString(in map[string]string) map[string]interface{} {
	result := make(map[string]interface{}, len(in))
	for k, v := range in {
		result[k] = v
	}
	return result
}

func convertMapInterfaceInterface(in map[interface{}]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(in))
	for k, v := range in {
		result[k.(string)] = v
	}
	return result
}

// ToString generates a human-readable representation of the current tree.
// Output spans multiple lines, and is suitable for ingest by a TOML parser.
// If the conversion cannot be performed, ToString returns a non-nil error.
func (t *TomlTree) ToString() (string, error) {
	return t.toTomlSafe("", "")
}

// String generates a human-readable representation of the current tree.
// Alias of ToString.
func (t *TomlTree) String() string {
	result, _ := t.ToString()
	return result
}

// ToMap recursively generates a representation of the current tree using map[string]interface{}.
func (t *TomlTree) ToMap() map[string]interface{} {
	result := map[string]interface{}{}

	for k, v := range t.values {
		switch node := v.(type) {
		case []*TomlTree:
			var array []interface{}
			for _, item := range node {
				array = append(array, item.ToMap())
			}
			result[k] = array
		case *TomlTree:
			result[k] = node.ToMap()
		case map[string]interface{}:
			sub := TreeFromMap(node)
			result[k] = sub.ToMap()
		case *tomlValue:
			result[k] = node.value
		}
	}

	return result
}
