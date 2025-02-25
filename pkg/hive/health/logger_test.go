package health

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive/health/types"
	"github.com/cilium/cilium/pkg/time"
)

func TestHealthLogger(t *testing.T) {
	now := time.Now
	t0 := time.Date(2000, 1, 1, 10, 30, 0, 0, time.UTC)
	time.Now = func() time.Time {
		return t0
	}
	since := time.Since
	time.Since = func(t time.Time) time.Duration {
		return t0.Sub(t)
	}
	t.Cleanup(func() { time.Now = now; time.Since = since })
	opts := &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, opts))

	db := statedb.New()
	tbl, err := newTablesPrivate(db)
	require.NoError(t, err)

	hl := &healthLogger{
		healthLoggerParams: healthLoggerParams{Log: log, DB: db, StatusTable: tbl},
		prevDegraded:       map[types.HealthID]types.Status{},
		since:              map[types.HealthID]time.Time{},
	}

	// With empty table report writes nothing.
	hl.report(context.TODO())
	require.Equal(t, "", buf.String())

	txn := db.WriteTxn(tbl)
	status := types.Status{
		ID:      types.Identifier{Module: []string{"foo", "bar"}, Component: []string{"baz"}},
		Level:   types.LevelDegraded,
		Message: "oh no",
		Error:   "some error",
		LastOK:  t0.Add(-2 * time.Minute),
		Updated: t0.Add(-time.Minute),
		Count:   1,
	}
	tbl.Insert(txn, status)
	txn.Commit()

	// With degraded status we'll get an health update
	hl.report(context.TODO())
	require.Equal(t,
		"level=INFO msg=\"--- Module health update ---\"\n"+
			"level=WARN msg=Degraded id=foo.bar.baz message=\"oh no\" error=\"some error\" since=1m0s\n",
		buf.String())
	buf.Reset()

	// With no changes to statuses nothing is logged.
	hl.report(context.TODO())
	require.Equal(t, "", buf.String())

	// Going back to OK will report recovery.
	status.Level = types.LevelOK
	status.Message = "all OK"
	status.Error = ""
	status.LastOK = t0
	status.Updated = t0
	txn = db.WriteTxn(tbl)
	tbl.Insert(txn, status)
	txn.Commit()
	hl.report(context.TODO())
	require.Equal(t,
		"level=INFO msg=\"--- Module health update ---\"\n"+
			"level=INFO msg=Recovered id=foo.bar.baz message=\"all OK\" old-message=\"oh no\" old-error=\"some error\" duration=1m0s\n",
		buf.String())
	buf.Reset()

	// With no changes to statuses nothing is logged.
	hl.report(context.TODO())
	require.Equal(t, "", buf.String())

	// As everything has recovered there should be no internal state anymore.
	require.Empty(t, hl.prevDegraded)
	require.Empty(t, hl.since)
}
