package config

import (
	"fmt"
	"reflect"

	proto "google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func Any(obj any) (*anypb.Any, error) {
	v := reflect.ValueOf(obj)

	if v.Kind() == reflect.Slice {
		if v.Len() != 1 {
			return nil, fmt.Errorf("slice does not have exactly one element: %d", v.Len())
		}

		obj = v.Index(0).Interface()
	}

	msg, ok := obj.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("obj does not implement proto.Message")
	}

	return anypb.New(msg)
}
