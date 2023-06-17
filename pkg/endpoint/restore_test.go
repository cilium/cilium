// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	linuxDatapath "github.com/cilium/cilium/pkg/datapath/linux"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/mac"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
)

func (ds *EndpointSuite) createEndpoints() ([]*Endpoint, map[uint16]*Endpoint) {
	epsWanted := []*Endpoint{
		ds.endpointCreator(256, identity.NumericIdentity(1256)),
		ds.endpointCreator(257, identity.NumericIdentity(1257)),
		ds.endpointCreator(258, identity.NumericIdentity(1258)),
		ds.endpointCreator(259, identity.NumericIdentity(1259)),
	}
	epsMap := map[uint16]*Endpoint{
		epsWanted[0].ID: epsWanted[0],
		epsWanted[1].ID: epsWanted[1],
		epsWanted[2].ID: epsWanted[2],
		epsWanted[3].ID: epsWanted[3],
	}
	return epsWanted, epsMap
}

func getStrID(id uint16) string {
	return fmt.Sprintf("%05d", id)
}

func (ds *EndpointSuite) endpointCreator(id uint16, secID identity.NumericIdentity) *Endpoint {
	strID := getStrID(id)
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, id)

	identity := &identity.Identity{
		ID: secID,
		Labels: labels.Labels{
			"foo" + strID: labels.NewLabel("foo"+strID, "", ""),
		},
	}
	identity.Sanitize()

	repo := ds.GetPolicyRepository()
	repo.GetPolicyCache().LocalEndpointIdentityAdded(identity)

	ep := NewEndpointWithState(ds, ds, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), id, StateReady)
	// Random network ID and docker endpoint ID with 59 hex chars + 5 strID = 64 hex chars
	ep.dockerNetworkID = "603e047d2268a57f5a5f93f7f9e1263e9207e348a06654bf64948def001" + strID
	ep.dockerEndpointID = "93529fda8c401a071d21d6bd46fdf5499b9014dcb5a35f2e3efaa8d8002" + strID
	ep.ifName = "lxc" + strID
	ep.mac = mac.MAC([]byte{0x01, 0xff, 0xf2, 0x12, b[0], b[1]})
	ep.IPv4 = netip.AddrFrom4([4]byte{0xc0, 0xa8, b[0], b[1]})
	ep.IPv6 = netip.AddrFrom16([16]byte{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, b[0], b[1]})
	ep.ifIndex = 1
	ep.nodeMAC = []byte{0x02, 0xff, 0xf2, 0x12, 0x0, 0x0}
	ep.SecurityIdentity = identity
	ep.OpLabels = labels.NewOpLabels()
	return ep
}

func (ds *EndpointSuite) TestReadEPsFromDirNames(c *C) {
	// For this test, the real linux datapath is necessary to properly
	// serialize config files to disk and test the restore.
	oldDatapath := ds.datapath
	defer func() {
		ds.datapath = oldDatapath
	}()
	ds.datapath = linuxDatapath.NewDatapath(linuxDatapath.DatapathConfiguration{}, nil, nil, nil)

	epsWanted, _ := ds.createEndpoints()
	tmpDir, err := os.MkdirTemp("", "cilium-tests")
	defer func() {
		os.RemoveAll(tmpDir)
	}()

	os.Chdir(tmpDir)
	c.Assert(err, IsNil)
	epsNames := []string{}
	for _, ep := range epsWanted {
		c.Assert(ep, NotNil)

		fullDirName := filepath.Join(tmpDir, ep.DirectoryPath())
		err := os.MkdirAll(fullDirName, 0777)
		c.Assert(err, IsNil)

		err = ep.writeHeaderfile(fullDirName)
		c.Assert(err, IsNil)

		switch ep.ID {
		case 256, 257:
			failedDir := filepath.Join(tmpDir, ep.FailedDirectoryPath())
			err := os.Rename(fullDirName, failedDir)
			c.Assert(err, IsNil)
			epsNames = append(epsNames, ep.FailedDirectoryPath())

			// create one failed and the other non failed directory for ep 256.
			if ep.ID == 256 {
				// Change endpoint a little bit so we know which endpoint is in
				// "256_next_fail" and with one is in the "256" directory.
				ep.nodeMAC = []byte{0x02, 0xff, 0xf2, 0x12, 0xc1, 0xc1}
				err = ep.writeHeaderfile(failedDir)
				c.Assert(err, IsNil)
			}
		default:
			epsNames = append(epsNames, ep.DirectoryPath())
		}
	}
	eps := ReadEPsFromDirNames(context.TODO(), ds, ds, ds, tmpDir, epsNames)
	c.Assert(len(eps), Equals, len(epsWanted))

	sort.Slice(epsWanted, func(i, j int) bool { return epsWanted[i].ID < epsWanted[j].ID })
	restoredEPs := make([]*Endpoint, 0, len(eps))
	for _, ep := range eps {
		restoredEPs = append(restoredEPs, ep)
	}
	sort.Slice(restoredEPs, func(i, j int) bool { return restoredEPs[i].ID < restoredEPs[j].ID })

	c.Assert(len(restoredEPs), Equals, len(epsWanted))
	for i, restoredEP := range restoredEPs {
		// We probably shouldn't modify these, but the status will
		// naturally differ between the wanted endpoint and the version
		// that's restored, because the restored version has log
		// messages relating to the restore.
		restoredEP.status = nil
		wanted := epsWanted[i]
		wanted.status = nil
		c.Assert(restoredEP.String(), checker.DeepEquals, wanted.String())
	}
}

func (ds *EndpointSuite) TestReadEPsFromDirNamesWithRestoreFailure(c *C) {
	// For this test, the real linux datapath is necessary to properly
	// serialize config files to disk and test the restore.
	oldDatapath := ds.datapath
	defer func() {
		ds.datapath = oldDatapath
	}()
	ds.datapath = linuxDatapath.NewDatapath(linuxDatapath.DatapathConfiguration{}, nil, nil, nil)

	eps, _ := ds.createEndpoints()
	ep := eps[0]
	c.Assert(ep, NotNil)
	tmpDir, err := os.MkdirTemp("", "cilium-tests")
	defer func() {
		os.RemoveAll(tmpDir)
	}()

	os.Chdir(tmpDir)
	c.Assert(err, IsNil)

	fullDirName := filepath.Join(tmpDir, ep.DirectoryPath())
	err = os.MkdirAll(fullDirName, 0777)
	c.Assert(err, IsNil)

	err = ep.writeHeaderfile(fullDirName)
	c.Assert(err, IsNil)

	nextDir := filepath.Join(tmpDir, ep.NextDirectoryPath())
	err = os.MkdirAll(nextDir, 0777)
	c.Assert(err, IsNil)

	// Change endpoint a little bit so we know which endpoint is in
	// "${EPID}_next" and with one is in the "${EPID}" directory.
	tmpNodeMAC := ep.nodeMAC
	ep.nodeMAC = []byte{0x02, 0xff, 0xf2, 0x12, 0xc1, 0xc1}
	err = ep.writeHeaderfile(nextDir)
	c.Assert(err, IsNil)
	ep.nodeMAC = tmpNodeMAC

	epNames := []string{
		ep.DirectoryPath(), ep.NextDirectoryPath(),
	}

	epResult := ReadEPsFromDirNames(context.TODO(), ds, ds, ds, tmpDir, epNames)
	c.Assert(len(epResult), Equals, 1)

	restoredEP := epResult[ep.ID]
	c.Assert(restoredEP.String(), checker.DeepEquals, ep.String())

	// Check that the directory for failed restore was removed.
	fileExists := func(fileName string) bool {
		_, err := os.Stat(fileName)
		if err == nil {
			return true
		}
		if !os.IsNotExist(err) {
			c.Assert(err, NotNil)
		}
		return false
	}
	c.Assert(fileExists(nextDir), checker.Equals, false)
	c.Assert(fileExists(fullDirName), checker.Equals, true)
}

func (ds *EndpointSuite) BenchmarkReadEPsFromDirNames(c *C) {
	c.StopTimer()

	// For this benchmark, the real linux datapath is necessary to properly
	// serialize config files to disk and benchmark the restore.
	oldDatapath := ds.datapath
	defer func() {
		ds.datapath = oldDatapath
	}()
	ds.datapath = linuxDatapath.NewDatapath(linuxDatapath.DatapathConfiguration{}, nil, nil, nil)

	epsWanted, _ := ds.createEndpoints()
	tmpDir, err := os.MkdirTemp("", "cilium-tests")
	defer func() {
		os.RemoveAll(tmpDir)
	}()

	os.Chdir(tmpDir)
	c.Assert(err, IsNil)
	epsNames := []string{}
	for _, ep := range epsWanted {
		c.Assert(ep, NotNil)

		fullDirName := filepath.Join(tmpDir, ep.DirectoryPath())
		err := os.MkdirAll(fullDirName, 0777)
		c.Assert(err, IsNil)

		err = ep.writeHeaderfile(fullDirName)
		c.Assert(err, IsNil)

		epsNames = append(epsNames, ep.DirectoryPath())
	}
	c.StartTimer()

	for i := 0; i < c.N; i++ {
		eps := ReadEPsFromDirNames(context.TODO(), ds, ds, ds, tmpDir, epsNames)
		c.Assert(len(eps), Equals, len(epsWanted))
	}
}

func (ds *EndpointSuite) TestPartitionEPDirNamesByRestoreStatus(c *C) {
	eptsDirNames := []string{
		"4", "12", "12_next", "3_next", "5_next_fail", "5",
	}
	completeWanted := []string{
		"12", "3_next", "4", "5",
	}
	incompleteWanted := []string{
		"12_next", "5_next_fail",
	}

	complete, incomplete := partitionEPDirNamesByRestoreStatus(eptsDirNames)

	sort.Strings(complete)
	sort.Strings(completeWanted)
	sort.Strings(incomplete)
	sort.Strings(incompleteWanted)
	c.Assert(complete, checker.DeepEquals, completeWanted)
	c.Assert(incomplete, checker.DeepEquals, incompleteWanted)
}
