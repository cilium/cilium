// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package annotation

import (
	"fmt"
	"strings"

	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
)

type UnsupportedProtoAction string

const (
	UnsupportedProtoActionUnspec  = UnsupportedProtoAction("")
	UnsupportedProtoActionDrop    = UnsupportedProtoAction(datapathOption.UnsupportedProtoActionDrop)
	UnsupportedProtoActionForward = UnsupportedProtoAction(datapathOption.UnsupportedProtoActionForward)
)

func GetAnnotationUnsupportedProtoAction(obj annotatedObject) (UnsupportedProtoAction, error) {
	if value, ok := Get(obj, NetworkUnsupportedProtoAction); ok {
		val := UnsupportedProtoAction(strings.ToLower(value))
		switch val {
		case UnsupportedProtoActionDrop, UnsupportedProtoActionForward:
			return val, nil
		default:
			return UnsupportedProtoActionUnspec, fmt.Errorf("value %q is not valid for annotation %q", value, NetworkUnsupportedProtoAction)
		}
	}
	return UnsupportedProtoActionUnspec, nil
}
