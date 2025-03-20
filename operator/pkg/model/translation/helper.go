// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// ParseNodeLabelSelector parses a given string representation of a label selector into a metav1.LabelSelector.
// The representation is a comma-separated list of key-value pairs (key1=value1,key2=value2) that is used as MatchLabels.
// Values not matching these rules are skipped.
func ParseNodeLabelSelector(nodeLabelSelectorString string) *slim_metav1.LabelSelector {
	if nodeLabelSelectorString == "" {
		return nil
	}

	labels := map[string]string{}
	for v := range strings.SplitSeq(nodeLabelSelectorString, ",") {
		s := strings.Split(v, "=")
		if len(s) != 2 || len(s[0]) == 0 {
			continue
		}
		labels[s[0]] = s[1]
	}

	return &slim_metav1.LabelSelector{
		MatchLabels: labels,
	}
}

func toXdsResource(m proto.Message, typeUrl string) (ciliumv2.XDSResource, error) {
	protoBytes, err := proto.Marshal(m)
	if err != nil {
		return ciliumv2.XDSResource{}, err
	}

	return ciliumv2.XDSResource{
		Any: &anypb.Any{
			TypeUrl: typeUrl,
			Value:   protoBytes,
		},
	}, nil
}

func toAny(message proto.Message) *anypb.Any {
	a, err := anypb.New(message)
	if err != nil {
		return nil
	}
	return a
}
