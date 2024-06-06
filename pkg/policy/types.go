package policy

import (
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

type PolicyManager interface {
	PolicyAdd(rules api.Rules, opts *AddOptions) (newRev uint64, err error)
	PolicyDelete(labels labels.LabelArray, opts *DeleteOptions) (newRev uint64, err error)
}
