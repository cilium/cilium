// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testutils

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/testing/protocmp"
)

func AssertProtoEqual(t *testing.T, want, got any, msgAndArgs ...any) bool {
	t.Helper()
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		return assert.Fail(t, fmt.Sprintf("not equal (-want +got):\n%s", diff), msgAndArgs...)
	}
	return true
}
