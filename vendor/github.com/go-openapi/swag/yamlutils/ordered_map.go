package yamlutils

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"

	"github.com/go-openapi/swag/jsonutils"
	yaml "gopkg.in/yaml.v3"
)

var (
	_ yaml.Marshaler = YAMLMapSlice{}
	// _ yaml.Unmarshaler = &YAMLMapSlice{} // TODO: implement yaml.Unmarshaler
)

// YAMLMapSlice represents a YAML object, with the order of keys maintained.
//
// It is similar to [jsonutils.JSONMapSlice] and also knows how to marshal and unmarshal YAML.
type YAMLMapSlice []YAMLMapItem

// YAMLMapItem represents the value of a key in a YAML object held by [YAMLMapSlice].
//
// It is entirely equivalent to [jsonutils.JSONMapItem], with the same limitation that
// you should not Marshal or Unmarshal directly this type, outside of a [YAMLMapSlice].
type YAMLMapItem = jsonutils.JSONMapItem

// MarshalJSON renders this YAML object as JSON bytes.
func (s YAMLMapSlice) MarshalJSON() ([]byte, error) {
	return jsonutils.JSONMapSlice(s).MarshalJSON()
}

// UnmarshalJSON builds this YAML object from JSON bytes.
func (s *YAMLMapSlice) UnmarshalJSON(data []byte) error {
	js := jsonutils.JSONMapSlice(*s)

	if err := js.UnmarshalJSON(data); err != nil {
		return err
	}

	*s = YAMLMapSlice(js)

	return nil
}

// MarshalYAML produces a YAML document as bytes
func (s YAMLMapSlice) MarshalYAML() (interface{}, error) {
	var n yaml.Node
	n.Kind = yaml.DocumentNode
	var nodes []*yaml.Node

	for _, item := range s {
		nn, err := json2yaml(item.Value)
		if err != nil {
			return nil, err
		}

		ns := []*yaml.Node{
			{
				Kind:  yaml.ScalarNode,
				Tag:   yamlStringScalar,
				Value: item.Key,
			},
			nn,
		}
		nodes = append(nodes, ns...)
	}

	n.Content = []*yaml.Node{
		{
			Kind:    yaml.MappingNode,
			Content: nodes,
		},
	}

	return yaml.Marshal(&n)
}

/*
// UnmarshalYAML builds a YAMLMapSlice object from a YAML document [yaml.Node].
func (s *YAMLMapSlice) UnmarshalYAML(value *yaml.Node) error {
	panic("not implemented")

	return nil
}
*/

func isNil(input interface{}) bool {
	if input == nil {
		return true
	}
	kind := reflect.TypeOf(input).Kind()
	switch kind { //nolint:exhaustive
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Chan:
		return reflect.ValueOf(input).IsNil()
	default:
		return false
	}
}

func json2yaml(item interface{}) (*yaml.Node, error) {
	if isNil(item) {
		return &yaml.Node{
			Kind:  yaml.ScalarNode,
			Value: "null",
		}, nil
	}

	switch val := item.(type) {
	case YAMLMapSlice:
		var n yaml.Node
		n.Kind = yaml.MappingNode
		for i := range val {
			childNode, err := json2yaml(val[i].Value)
			if err != nil {
				return nil, err
			}
			n.Content = append(n.Content, &yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   yamlStringScalar,
				Value: val[i].Key,
			}, childNode)
		}
		return &n, nil

	case jsonutils.JSONMapSlice:
		var n yaml.Node
		n.Kind = yaml.MappingNode
		for i := range val {
			childNode, err := json2yaml(val[i].Value)
			if err != nil {
				return nil, err
			}
			n.Content = append(n.Content, &yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   yamlStringScalar,
				Value: val[i].Key,
			}, childNode)
		}
		return &n, nil

	case map[string]interface{}:
		var n yaml.Node
		n.Kind = yaml.MappingNode
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			v := val[k]
			childNode, err := json2yaml(v)
			if err != nil {
				return nil, err
			}
			n.Content = append(n.Content, &yaml.Node{
				Kind:  yaml.ScalarNode,
				Tag:   yamlStringScalar,
				Value: k,
			}, childNode)
		}
		return &n, nil

	case []interface{}:
		var n yaml.Node
		n.Kind = yaml.SequenceNode
		for i := range val {
			childNode, err := json2yaml(val[i])
			if err != nil {
				return nil, err
			}
			n.Content = append(n.Content, childNode)
		}
		return &n, nil
	case string:
		return &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   yamlStringScalar,
			Value: val,
		}, nil
	case float64:
		return &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   yamlFloatScalar,
			Value: strconv.FormatFloat(val, 'f', -1, 64),
		}, nil
	case int64:
		return &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   yamlIntScalar,
			Value: strconv.FormatInt(val, 10),
		}, nil
	case uint64:
		return &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   yamlIntScalar,
			Value: strconv.FormatUint(val, 10),
		}, nil
	case bool:
		return &yaml.Node{
			Kind:  yaml.ScalarNode,
			Tag:   yamlBoolScalar,
			Value: strconv.FormatBool(val),
		}, nil
	default:
		return nil, fmt.Errorf("unhandled type: %T: %w", val, ErrYAML)
	}
}
