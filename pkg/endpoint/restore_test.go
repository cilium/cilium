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
	"testing"

	"github.com/stretchr/testify/require"

	fake "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
)

func (s *EndpointSuite) createEndpoints() ([]*Endpoint, map[uint16]*Endpoint) {
	epsWanted := []*Endpoint{
		s.endpointCreator(256, identity.NumericIdentity(1256)),
		s.endpointCreator(257, identity.NumericIdentity(1257)),
		s.endpointCreator(258, identity.NumericIdentity(1258)),
		s.endpointCreator(259, identity.NumericIdentity(1259)),
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

func (s *EndpointSuite) endpointCreator(id uint16, secID identity.NumericIdentity) *Endpoint {
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

	repo := s.GetPolicyRepository()
	repo.GetPolicyCache().LocalEndpointIdentityAdded(identity)

	ep := NewTestEndpointWithState(nil, s, s, testipcache.NewMockIPCache(), &FakeEndpointProxy{}, testidentity.NewMockIdentityAllocator(nil), id, StateReady)
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
	ep.NetNsCookie = 1234
	return ep
}

func TestReadEPsFromDirNames(t *testing.T) {
	s := setupEndpointSuite(t)
	oldDatapath := s.datapath
	defer func() {
		s.datapath = oldDatapath
	}()

	s.datapath = fake.NewDatapath()
	epsWanted, _ := s.createEndpoints()
	tmpDir, err := os.MkdirTemp("", "cilium-tests")
	defer func() {
		os.RemoveAll(tmpDir)
	}()

	const unsupportedTestOption = "unsupported-test-only-option-xyz"

	os.Chdir(tmpDir)
	require.Nil(t, err)
	epsNames := []string{}
	for _, ep := range epsWanted {
		require.NotNil(t, ep)

		fullDirName := filepath.Join(tmpDir, ep.DirectoryPath())
		err := os.MkdirAll(fullDirName, 0777)
		require.Nil(t, err)

		// Add an unsupported option and see that it is removed on "restart"
		ep.Options.SetValidated(unsupportedTestOption, option.OptionEnabled)

		err = ep.writeHeaderfile(fullDirName)
		require.Nil(t, err)

		// Remove unsupported option so that equality check works after restore
		ep.Options.Delete(unsupportedTestOption)

		switch ep.ID {
		case 256, 257:
			failedDir := filepath.Join(tmpDir, ep.FailedDirectoryPath())
			err := os.Rename(fullDirName, failedDir)
			require.Nil(t, err)
			epsNames = append(epsNames, ep.FailedDirectoryPath())

			// create one failed and the other non failed directory for ep 256.
			if ep.ID == 256 {
				// Change endpoint a little bit so we know which endpoint is in
				// "256_next_fail" and with one is in the "256" directory.
				ep.nodeMAC = []byte{0x02, 0xff, 0xf2, 0x12, 0xc1, 0xc1}
				err = ep.writeHeaderfile(failedDir)
				require.Nil(t, err)
			}
		default:
			epsNames = append(epsNames, ep.DirectoryPath())
		}
	}
	eps := ReadEPsFromDirNames(context.TODO(), s, s, s, tmpDir, epsNames)
	require.Equal(t, len(epsWanted), len(eps))

	sort.Slice(epsWanted, func(i, j int) bool { return epsWanted[i].ID < epsWanted[j].ID })
	restoredEPs := make([]*Endpoint, 0, len(eps))
	for _, ep := range eps {
		restoredEPs = append(restoredEPs, ep)
	}
	sort.Slice(restoredEPs, func(i, j int) bool { return restoredEPs[i].ID < restoredEPs[j].ID })

	require.Equal(t, len(epsWanted), len(restoredEPs))
	for i, restoredEP := range restoredEPs {
		// We probably shouldn't modify these, but the status will
		// naturally differ between the wanted endpoint and the version
		// that's restored, because the restored version has log
		// messages relating to the restore.
		restoredEP.status = nil
		wanted := epsWanted[i]
		wanted.status = nil
		require.EqualValues(t, wanted.String(), restoredEP.String())
	}
}

func TestReadEPsFromDirNamesWithRestoreFailure(t *testing.T) {
	s := setupEndpointSuite(t)

	oldDatapath := s.datapath
	defer func() {
		s.datapath = oldDatapath
	}()

	s.datapath = fake.NewDatapath()

	eps, _ := s.createEndpoints()
	ep := eps[0]
	require.NotNil(t, ep)
	tmpDir, err := os.MkdirTemp("", "cilium-tests")
	defer func() {
		os.RemoveAll(tmpDir)
	}()

	os.Chdir(tmpDir)
	require.Nil(t, err)

	fullDirName := filepath.Join(tmpDir, ep.DirectoryPath())
	err = os.MkdirAll(fullDirName, 0777)
	require.Nil(t, err)

	err = ep.writeHeaderfile(fullDirName)
	require.Nil(t, err)

	nextDir := filepath.Join(tmpDir, ep.NextDirectoryPath())
	err = os.MkdirAll(nextDir, 0777)
	require.Nil(t, err)

	// Change endpoint a little bit so we know which endpoint is in
	// "${EPID}_next" and with one is in the "${EPID}" directory.
	tmpNodeMAC := ep.nodeMAC
	ep.nodeMAC = []byte{0x02, 0xff, 0xf2, 0x12, 0xc1, 0xc1}
	err = ep.writeHeaderfile(nextDir)
	require.Nil(t, err)
	ep.nodeMAC = tmpNodeMAC

	epNames := []string{
		ep.DirectoryPath(), ep.NextDirectoryPath(),
	}

	epResult := ReadEPsFromDirNames(context.TODO(), s, s, s, tmpDir, epNames)
	require.Equal(t, 1, len(epResult))

	restoredEP := epResult[ep.ID]
	require.EqualValues(t, ep.String(), restoredEP.String())

	// Check that the directory for failed restore was removed.
	fileExists := func(fileName string) bool {
		_, err := os.Stat(fileName)
		if err == nil {
			return true
		}
		if !os.IsNotExist(err) {
			require.Error(t, err)
		}
		return false
	}
	require.Equal(t, false, fileExists(nextDir))
	require.Equal(t, true, fileExists(fullDirName))
}

func BenchmarkReadEPsFromDirNames(b *testing.B) {
	s := setupEndpointSuite(b)

	b.StopTimer()

	// For this benchmark, the real linux datapath is necessary to properly
	// serialize config files to disk and benchmark the restore.
	oldDatapath := s.datapath
	defer func() {
		s.datapath = oldDatapath
	}()

	s.datapath = fake.NewDatapath()

	epsWanted, _ := s.createEndpoints()
	tmpDir, err := os.MkdirTemp("", "cilium-tests")
	defer func() {
		os.RemoveAll(tmpDir)
	}()

	os.Chdir(tmpDir)
	require.Nil(b, err)
	epsNames := []string{}
	for _, ep := range epsWanted {
		require.NotNil(b, ep)

		fullDirName := filepath.Join(tmpDir, ep.DirectoryPath())
		err := os.MkdirAll(fullDirName, 0777)
		require.Nil(b, err)

		err = ep.writeHeaderfile(fullDirName)
		require.Nil(b, err)

		epsNames = append(epsNames, ep.DirectoryPath())
	}
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		eps := ReadEPsFromDirNames(context.TODO(), s, s, s, tmpDir, epsNames)
		require.Equal(b, len(epsWanted), len(eps))
	}
}

func TestPartitionEPDirNamesByRestoreStatus(t *testing.T) {
	setupEndpointSuite(t)

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
	require.EqualValues(t, completeWanted, complete)
	require.EqualValues(t, incompleteWanted, incomplete)
}
