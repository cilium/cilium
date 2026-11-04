// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var cmpIgnoreFields = cmp.Options{
	// The controller-runtime fake client clears TypeMeta when objects are read.
	cmpopts.IgnoreFields(metav1.TypeMeta{}, "Kind", "APIVersion"),
	cmpopts.IgnoreFields(metav1.ObjectMeta{}, "ResourceVersion"),
	cmpopts.IgnoreFields(metav1.Condition{}, "LastTransitionTime"),
}
