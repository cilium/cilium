package controlplane

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/cilium/demo/datapath"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func BenchmarkControlPlane(b *testing.B) {
	type params struct {
		cell.In

		DB        *statedb.DB
		Services  statedb.RWTable[*Service]
		Endpoints statedb.RWTable[*Endpoint]

		Frontends statedb.Table[*datapath.Frontend]
		Backends  statedb.Table[*datapath.Backend]
	}

	var p params

	logging.SetLogLevel(logrus.ErrorLevel)

	h := hive.New(
		job.Cell,
		statedb.Cell,

		// Output tables
		cell.Provide(
			datapath.NewFrontends,
			datapath.NewBackends,
		),

		tablesCell,
		servicesControllerCell,

		cell.Invoke(func(p_ params) { p = p_ }),
	)

	require.NoError(b, h.Start(context.TODO()))

	numServicesOrEndpoints := b.N

	wtxn := p.DB.WriteTxn(p.Services, p.Endpoints)
	for i := 0; i < numServicesOrEndpoints; i++ {
		name := fmt.Sprintf("svc%d", i)
		var addr1, addr2 [4]byte
		binary.BigEndian.PutUint32(addr1[:], 0x01000000+uint32(i))
		binary.BigEndian.PutUint32(addr2[:], 0x02000000+uint32(i))
		_, _, err := p.Services.Insert(
			wtxn,
			&Service{
				Name:        name,
				Source:      "test",
				ServiceType: "NodePort",
				ClusterIP:   netip.AddrFrom4(addr1),
				Port:        uint16(10 + i),
				Protocol:    "TCP",
			},
		)
		require.NoError(b, err, "Services.Insert")

		_, _, err = p.Endpoints.Insert(
			wtxn,
			&Endpoint{
				Source:  "test",
				Service: name,
				Addrs:   []netip.Addr{netip.AddrFrom4(addr2)},
				Ports: []PortAndProtocol{
					{
						Port:     uint16(20 + i),
						Protocol: "TCP",
					},
				},
			},
		)
		require.NoError(b, err, "Endpoints.Insert")
	}

	// Now that bulk of the insertion work is done, reset the timer to only
	// count how long it takes for the services controller.
	b.ResetTimer()

	wtxn.Commit()

	// Wait until reconciled.
	assert.Eventually(b,
		func() bool {
			txn := p.DB.ReadTxn()
			return p.Frontends.NumObjects(txn) == numServicesOrEndpoints &&
				p.Backends.NumObjects(txn) == numServicesOrEndpoints
		},
		10*time.Second,
		50*time.Millisecond)

	require.NoError(b, h.Stop(context.TODO()))

}
