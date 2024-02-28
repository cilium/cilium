// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"context"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
)

func TestDefaultRoutes(t *testing.T) {
	h := hive.New(
		statedb.Cell,
		cell.Provide(NewRouteTable),
		cell.Invoke(statedb.RegisterTable[*Route]),
		cell.Invoke(func(db *statedb.DB, tbl statedb.RWTable[*Route]) {
			tx := db.WriteTxn(tbl)
			var err error

			def1 := &Route{
				Table:     unix.RT_TABLE_MAIN,
				LinkIndex: 1,
				Dst:       zeroPrefixV4,
			}
			_, _, err = tbl.Insert(tx, def1)
			assert.NoError(t, err)

			_, _, err = tbl.Insert(tx, &Route{
				Table:     123,
				LinkIndex: 2,
				Dst:       zeroPrefixV4,
			})
			assert.NoError(t, err)

			def2 := &Route{
				Table:     unix.RT_TABLE_MAIN,
				LinkIndex: 3,
				Dst:       zeroPrefixV6,
			}
			_, _, err = tbl.Insert(tx, def2)
			assert.NoError(t, err)

			_, _, err = tbl.Insert(tx, &Route{
				Table:     123,
				LinkIndex: 4,
				Dst:       zeroPrefixV6,
			})
			assert.NoError(t, err)

			_, _, err = tbl.Insert(tx, &Route{
				Table:     unix.RT_TABLE_MAIN,
				LinkIndex: 5,
				Dst:       netip.MustParsePrefix("10.0.0.1/32"),
			})
			assert.NoError(t, err)

			_, _, err = tbl.Insert(tx, &Route{
				Table:     unix.RT_TABLE_MAIN,
				LinkIndex: 6,
				Dst:       netip.MustParsePrefix("ff::10/32"),
			})
			assert.NoError(t, err)
			tx.Commit()

			rx := db.ReadTxn()
			routes := GetDefaultRoutes(tbl, rx)
			assert.Len(t, routes, 2)
			assert.Contains(t, routes, def1)
			assert.Contains(t, routes, def2)
		}),
	)

	h.Start(context.Background())
	h.Stop(context.Background())
}
