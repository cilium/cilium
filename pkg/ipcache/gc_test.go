// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type dummyReleaser struct {
	released map[string]int
}

func newDummyReleaser() *dummyReleaser {
	return &dummyReleaser{released: make(map[string]int)}
}

func (d *dummyReleaser) releaseCIDRIdentities(ctx context.Context, prefixes []netip.Prefix) {
	for _, prefix := range prefixes {
		p := prefix.String()
		count := d.released[p]
		d.released[p] = count + 1
	}
}

func TestDeferRelease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	prefix := netip.MustParsePrefix("192.0.2.3/32")
	parent := newDummyReleaser()
	// set a high interval so we can manually test the internals without
	// racing against the trigger that's set up in the constructor.
	releaser := newAsyncPrefixReleaser(ctx, parent, 5*time.Minute)

	releaser.enqueue([]netip.Prefix{prefix, prefix}, "test enqueue basics")
	releaser.run(ctx)
	remaining := releaser.dequeue()
	assert.Len(t, remaining, 0)
	assert.Equal(t, 2, parent.released[prefix.String()])
	remaining = releaser.dequeue()
	assert.Len(t, remaining, 0)

	parent = newDummyReleaser()
	releaser = newAsyncPrefixReleaser(ctx, parent, 5*time.Minute)
	newPrefix := netip.MustParsePrefix("0.0.0.0/0")
	releaser.enqueue([]netip.Prefix{prefix, newPrefix}, "multiple inputs")
	releaser.run(ctx)
	remaining = releaser.dequeue()
	assert.Len(t, remaining, 0)
	assert.Equal(t, 1, parent.released[prefix.String()])
	assert.Equal(t, 1, parent.released[newPrefix.String()])
}
