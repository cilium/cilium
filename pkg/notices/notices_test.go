// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package notices

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/time"
)

func TestNotices(t *testing.T) {
	var (
		db          *statedb.DB
		noticeTable statedb.Table[Notice]
		notices     Notices
	)

	h := hive.New(
		Cell,
		cell.Invoke(
			func(db_ *statedb.DB, n Notices, tbl statedb.Table[Notice]) {
				db = db_
				notices = n
				noticeTable = tbl
			},
		),
	)
	log := hivetest.Logger(t)
	require.NoError(t, h.Start(log, context.TODO()), "Start")
	defer h.Stop(log, context.TODO())

	// No notices when we start.
	require.Zero(t, noticeTable.NumObjects(db.ReadTxn()))

	// Post some notices
	notices.Post("title1", "message1", time.Minute)
	notices.Post("title2", "message2", time.Minute)
	allNotices := notices.All()
	require.Len(t, allNotices, 2)
	// Sorted by title.
	require.Equal(t, "title1", allNotices[0].Title)
	require.Equal(t, "message1", allNotices[0].Message)
	require.Equal(t, "title2", allNotices[1].Title)
	require.Equal(t, "message2", allNotices[1].Message)

	// Retract the first notice.
	notices.Retract("title1")
	require.Equal(t, 1, noticeTable.NumObjects(db.ReadTxn()))

	// Retract the final notice.
	notices.Retract("title2")
	require.Zero(t, noticeTable.NumObjects(db.ReadTxn()))

	// Test cleanup by posting a notice with tiny TTL
	notices.Post("title1", "message1", time.Nanosecond)

	// It'll still be there as the default interval is long.
	require.Equal(t, 1, noticeTable.NumObjects(db.ReadTxn()))

	// Force the cleanup and check again.
	notices.periodicCleanup(context.TODO())
	require.Zero(t, noticeTable.NumObjects(db.ReadTxn()))
}

func TestPostHealth(t *testing.T) {
	var (
		db          *statedb.DB
		noticeTable statedb.Table[Notice]
	)

	h := hive.New(
		Cell,
		cell.Invoke(
			func(db_ *statedb.DB, tbl statedb.Table[Notice]) {
				db = db_
				noticeTable = tbl
			},
		),
		cell.Module("test", "test",
			cell.Invoke(func(h cell.Health) {
				h.Degraded("oh no", errors.New("err"))
			}),
		),
	)

	// Set the interval very small to speed up the test.
	healthPostInterval = time.Millisecond * 5

	log := hivetest.Logger(t)
	require.NoError(t, h.Start(log, context.TODO()), "Start")
	defer h.Stop(log, context.TODO())

	require.Eventually(
		t,
		func() bool {
			n, _, found := noticeTable.Get(db.ReadTxn(), ByTitle(healthTitle))
			if !found {
				return false
			}
			ok := n.Title == healthTitle && strings.HasPrefix(n.Message, "Degraded: 1 unhealthy component(s). Oldest: test:")
			if !ok {
				t.Logf("notice: %v", n)
			}
			return ok
		},
		time.Second,
		100*time.Millisecond,
	)

}
