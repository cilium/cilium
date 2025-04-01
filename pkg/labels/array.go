// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	v2 "github.com/cilium/cilium/pkg/labels/v2"
)

// LabelArray is an array of labels forming a set
type LabelArray = v2.LabelArray

// ParseLabelArray parses a list of labels and returns a LabelArray
var ParseLabelArray = v2.ParseLabelArray

// ParseSelectLabelArray parses a list of select labels and returns a LabelArray
var ParseSelectLabelArray = v2.ParseSelectLabelArray

// ParseLabelArrayFromArray converts an array of strings as labels and returns a LabelArray
var ParseLabelArrayFromArray = v2.ParseLabelArrayFromArray

// NewLabelArrayFromSortedList returns labels based on the output of SortedList()
// Trailing ';' will result in an empty key that must be filtered out.
var NewLabelArrayFromSortedList = v2.NewLabelArrayFromSortedList

// ParseSelectLabelArrayFromArray converts an array of strings as select labels and returns a LabelArray
var ParseSelectLabelArrayFromArray = v2.ParseSelectLabelArrayFromArray

var LabelArrayFromString = v2.LabelArrayFromString
