// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type responseMetadataForTest struct {
	ctx context.Context
}

func (response responseMetadataForTest) GetContext() context.Context {
	return response.ctx
}

func TestDeltaWildcardCoverageSeparatesReconciliationFromPayload(t *testing.T) {
	coverage := &responseCoverage{
		returned: map[string]string{"changed": "version"},
		delta:    true,
		full:     true,
	}
	require.True(t, coverage.complete())
	require.True(t, coverage.contains("unchanged"),
		"a wildcard ACK reconciles unchanged resources from the client version map")
	require.True(t, coverage.containsChange("changed"))
	require.False(t, coverage.containsChange("unchanged"),
		"an unchanged resource cannot be rejected by a response that omitted it")

	ctx := WithSnapshotGeneration(t.Context(), Generation(5))
	ctx = context.WithValue(ctx, responseCoverageContextKey{}, coverage)
	response := responseMetadataForTest{ctx: ctx}
	require.True(t, ResponseCoversResource(response, "changed", Generation(5).TransactionID()))
	require.False(t, ResponseCoversResource(response, "unchanged", Generation(5).TransactionID()))

	changedScope := SingleResourceScope("changed", Generation(5).Revision())
	unchangedScope := SingleResourceScope("unchanged", Generation(5).Revision())
	require.True(t, changedScope.intersectsChanges(coverage, Generation(5)))
	require.True(t, unchangedScope.intersects(coverage, Generation(5)),
		"the ACK reconciles the unchanged resource")
	require.False(t, unchangedScope.intersectsChanges(coverage, Generation(5)),
		"the NACK cannot reject the unchanged resource")

	require.False(t, ResponseCoversType(response, Generation(5)),
		"Delta rollback ownership is always selected from explicit response changes")
}
