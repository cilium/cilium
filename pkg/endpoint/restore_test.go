// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	fakeendpoint "github.com/cilium/cilium/pkg/endpoint/fake"
	fqdnrestore "github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"
)

func (s *EndpointSuite) createEndpointParams(tb testing.TB) EndpointParams {
	return createEndpointParams(tb, s.orchestrator, s.repo, s.fetcher)
}

func (s *EndpointSuite) createEndpoints(t testing.TB) ([]*Endpoint, map[uint16]*Endpoint) {
	p := s.createEndpointParams(t)
	epsWanted := []*Endpoint{
		s.endpointCreator(t, 256, identity.NumericIdentity(1256), p),
		s.endpointCreator(t, 257, identity.NumericIdentity(1257), p),
		s.endpointCreator(t, 258, identity.NumericIdentity(1258), p),
		s.endpointCreator(t, 259, identity.NumericIdentity(1259), p),
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

func (s *EndpointSuite) endpointCreator(t testing.TB, id uint16, secID identity.NumericIdentity, p EndpointParams) *Endpoint {
	strID := getStrID(id)
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, id)

	identity := &identity.Identity{
		ID: secID,
		Labels: labels.Labels{
			"foo" + strID: labels.NewLabel("foo"+strID, "", ""),
		},
	}

	model := newTestEndpointModel(int(id), StateReady)
	ep, err := NewEndpointFromChangeModel(p, nil, &FakeEndpointProxy{}, model, nil)
	require.NoError(t, err)

	ep.Start(uint16(model.ID))
	t.Cleanup(ep.Stop)

	ep.ifName = "lxc" + strID
	ep.mac = mac.MAC{0x01, 0xff, 0xf2, 0x12, b[0], b[1]}
	ep.IPv4 = netip.AddrFrom4([4]byte{0xc0, 0xa8, b[0], b[1]})
	ep.IPv6 = netip.AddrFrom16([16]byte{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, b[0], b[1]})
	ep.ifIndex = 1
	ep.nodeMAC = mac.MAC{0x02, 0xff, 0xf2, 0x12, 0x0, 0x0}
	ep.SecurityIdentity = identity
	ep.labels = labels.NewOpLabels()
	ep.NetNsCookie = 1234
	return ep
}

func TestReadEPsFromDirNames(t *testing.T) {
	logger := hivetest.Logger(t)
	s := setupEndpointSuite(t)
	epsWanted, _ := s.createEndpoints(t)
	tmpDir := t.TempDir()

	const unsupportedTestOption = "unsupported-test-only-option-xyz"

	cwd, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		os.Chdir(cwd)
	}()
	os.Chdir(tmpDir)
	require.NoError(t, err)
	epsNames := []string{}
	for _, ep := range epsWanted {
		require.NotNil(t, ep)

		fullDirName := filepath.Join(tmpDir, ep.DirectoryPath())
		err := os.MkdirAll(fullDirName, 0o777)
		require.NoError(t, err)

		// Add an unsupported option and see that it is removed on "restart"
		ep.Options.SetValidated(unsupportedTestOption, option.OptionEnabled)

		err = ep.writeHeaderfile(fullDirName)
		require.NoError(t, err)

		// Remove unsupported option so that equality check works after restore
		ep.Options.Delete(unsupportedTestOption)

		switch ep.ID {
		case 256, 257:
			failedDir := filepath.Join(tmpDir, ep.FailedDirectoryPath())
			err := os.Rename(fullDirName, failedDir)
			require.NoError(t, err)
			epsNames = append(epsNames, ep.FailedDirectoryPath())

			// create one failed and the other non failed directory for ep 256.
			if ep.ID == 256 {
				// Change endpoint a little bit so we know which endpoint is in
				// "256_next_fail" and with one is in the "256" directory.
				ep.nodeMAC = mac.MAC{0x02, 0xff, 0xf2, 0x12, 0xc1, 0xc1}
				err = ep.writeHeaderfile(failedDir)
				require.NoError(t, err)
			}
		default:
			epsNames = append(epsNames, ep.DirectoryPath())
		}
	}
	eps, _ := ReadEPsFromDirNames(context.TODO(), logger, &fakeParser{p: s.createEndpointParams(t)}, tmpDir, epsNames)
	require.Len(t, eps, len(epsWanted))

	sort.Slice(epsWanted, func(i, j int) bool { return epsWanted[i].ID < epsWanted[j].ID })
	restoredEPs := make([]*Endpoint, 0, len(eps))
	for _, ep := range eps {
		restoredEPs = append(restoredEPs, ep)
	}
	sort.Slice(restoredEPs, func(i, j int) bool { return restoredEPs[i].ID < restoredEPs[j].ID })

	require.Len(t, restoredEPs, len(epsWanted))
	for i, restoredEP := range restoredEPs {
		// We probably shouldn't modify these, but the status will
		// naturally differ between the wanted endpoint and the version
		// that's restored, because the restored version has log
		// messages relating to the restore.
		restoredEP.status = nil
		wanted := epsWanted[i]
		wanted.status = nil
		require.Equal(t, wanted.String(), restoredEP.String())
	}
}

func TestReadEPsFromDirNamesWithRestoreFailure(t *testing.T) {
	logger := hivetest.Logger(t)
	s := setupEndpointSuite(t)

	eps, _ := s.createEndpoints(t)
	ep := eps[0]
	require.NotNil(t, ep)
	tmpDir := t.TempDir()

	cwd, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		os.Chdir(cwd)
	}()
	os.Chdir(tmpDir)
	require.NoError(t, err)

	fullDirName := filepath.Join(tmpDir, ep.DirectoryPath())
	err = os.MkdirAll(fullDirName, 0o777)
	require.NoError(t, err)

	err = ep.writeHeaderfile(fullDirName)
	require.NoError(t, err)

	nextDir := filepath.Join(tmpDir, ep.NextDirectoryPath())
	err = os.MkdirAll(nextDir, 0o777)
	require.NoError(t, err)

	// Change endpoint a little bit so we know which endpoint is in
	// "${EPID}_next" and with one is in the "${EPID}" directory.
	tmpNodeMAC := ep.nodeMAC
	ep.nodeMAC = mac.MAC{0x02, 0xff, 0xf2, 0x12, 0xc1, 0xc1}
	err = ep.writeHeaderfile(nextDir)
	require.NoError(t, err)
	ep.nodeMAC = tmpNodeMAC

	epNames := []string{
		ep.DirectoryPath(), ep.NextDirectoryPath(),
	}

	epResult, _ := ReadEPsFromDirNames(context.TODO(), logger, &fakeParser{p: s.createEndpointParams(t)}, tmpDir, epNames)
	require.Len(t, epResult, 1)

	restoredEP := epResult[ep.ID]
	require.Equal(t, ep.String(), restoredEP.String())

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
	require.False(t, fileExists(nextDir))
	require.True(t, fileExists(fullDirName))
}

func BenchmarkReadEPsFromDirNames(b *testing.B) {
	logger := hivetest.Logger(b)
	s := setupEndpointSuite(b)

	// For this benchmark, the real linux datapath is necessary to properly
	// serialize config files to disk and benchmark the restore.

	epsWanted, _ := s.createEndpoints(b)
	tmpDir := b.TempDir()

	cwd, err := os.Getwd()
	require.NoError(b, err)
	defer func() {
		os.Chdir(cwd)
	}()
	os.Chdir(tmpDir)
	require.NoError(b, err)
	epsNames := []string{}
	for _, ep := range epsWanted {
		require.NotNil(b, ep)

		fullDirName := filepath.Join(tmpDir, ep.DirectoryPath())
		err := os.MkdirAll(fullDirName, 0o777)
		require.NoError(b, err)

		err = ep.writeHeaderfile(fullDirName)
		require.NoError(b, err)

		epsNames = append(epsNames, ep.DirectoryPath())
	}

	for b.Loop() {
		eps, _ := ReadEPsFromDirNames(context.TODO(), logger, &fakeParser{p: s.createEndpointParams(b)}, tmpDir, epsNames)
		require.Len(b, eps, len(epsWanted))
	}
}

func TestSerializableEndpointUnmarshalDNSRulesV2(t *testing.T) {
	v1Rules := fqdnrestore.DNSRules{
		fqdnrestore.PortProto(5353): {},
	}
	v2Rules := fqdnrestore.DNSRules{
		fqdnrestore.MakeV2PortProto(53, u8proto.UDP): {},
	}

	raw, err := json.Marshal(map[string]any{
		"DNSRules":   v1Rules,
		"DNSRulesV2": v2Rules,
	})
	require.NoError(t, err)

	var restored serializableEndpoint
	require.NoError(t, json.Unmarshal(raw, &restored))
	require.Equal(t, v1Rules, restored.DNSRulesUnused)
	require.Equal(t, v2Rules, restored.DNSRules)

	ep := &Endpoint{}
	ep.fromSerializedEndpoint(&restored)
	require.Equal(t, v2Rules, ep.DNSRules)
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

	slices.Sort(complete)
	slices.Sort(completeWanted)
	slices.Sort(incomplete)
	slices.Sort(incompleteWanted)
	require.Equal(t, completeWanted, complete)
	require.Equal(t, incompleteWanted, incomplete)
}

type fakeParser struct {
	p EndpointParams
}

func (f *fakeParser) ParseEndpoint(epJSON []byte) (*Endpoint, error) {
	return ParseEndpoint(f.p, nil, nil, epJSON, nil)
}

var _ EndpointParser = &fakeParser{}

func TestSyncEndpointHeaderFilePersistsCiliumEndpointUID(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode string
	}{
		{
			name: "sync_after_trigger_initialized",
			mode: "after",
		},
		{
			name: "sync_before_trigger_initialized",
			mode: "before",
		},
		{
			name: "sync_concurrent_with_trigger_init",
			mode: "concurrent",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			tmpDir := t.TempDir()
			origStateDir := option.Config.StateDir
			option.Config.StateDir = tmpDir
			t.Cleanup(func() {
				option.Config.StateDir = origStateDir
			})

			idmgr := identitymanager.NewIDManager(logger)
			repo := policy.NewPolicyRepository(logger, cmtypes.DefaultClusterInfo, nil, nil, nil, idmgr, testpolicy.NewPolicyMetricsNoop())
			p := createEndpointParams(t, &fakeendpoint.FakeOrchestrator{}, repo, nil)
			model := newTestEndpointModel(256, StateWaitingForIdentity)
			ep, err := NewEndpointFromChangeModel(p, &fakeDNSRulesAPI{}, &FakeEndpointProxy{}, model, nil)
			require.NoError(t, err)
			ep.Start(uint16(model.ID))
			t.Cleanup(func() {
				ep.SetState(StateDisconnecting, "test")
				ep.Stop()
			})
			stateDir := ep.StateDirectoryPath()
			require.NoError(t, os.MkdirAll(stateDir, 0o777))

			// Persist initial CEP UID ("cep-uid-1") to ep_config.json on disk.
			ep.SetCiliumEndpointUID(types.UID("cep-uid-1"))
			require.NoError(t, ep.writeHeaderfile(stateDir))

			// Simulate CEP recreation updating CiliumEndpointUID to "cep-uid-2" and syncing header file.
			switch tc.mode {
			case "before":
				ep.SetCiliumEndpointUID(types.UID("cep-uid-2"))
				ep.SyncEndpointHeaderFile()
				ep.initDNSHistoryTrigger()
			case "after":
				ep.initDNSHistoryTrigger()
				ep.SetCiliumEndpointUID(types.UID("cep-uid-2"))
				ep.SyncEndpointHeaderFile()
			case "concurrent":
				ep.SetCiliumEndpointUID(types.UID("cep-uid-2"))
				start := make(chan struct{})
				var wg sync.WaitGroup
				wg.Add(2)
				go func() {
					defer wg.Done()
					<-start
					ep.SyncEndpointHeaderFile()
				}()
				go func() {
					defer wg.Done()
					<-start
					ep.initDNSHistoryTrigger()
				}()
				close(start)
				wg.Wait()
			}

			require.EventuallyWithT(t, func(c *assert.CollectT) {
				eps, _ := ReadEPsFromDirNames(
					t.Context(),
					logger,
					&fakeParser{p: p},
					tmpDir,
					[]string{ep.DirectoryPath()},
				)
				if assert.Len(c, eps, 1) {
					assert.Equal(c, types.UID("cep-uid-2"), eps[ep.ID].GetCiliumEndpointUID())
				}
			}, 2*time.Second, 20*time.Millisecond)
		})
	}
}

type fakeDNSRulesAPI struct{}

func (f *fakeDNSRulesAPI) GetDNSRules(_ uint16) fqdnrestore.DNSRules { return nil }
func (f *fakeDNSRulesAPI) RestoreDNSRules(_ uint16, _ fqdnrestore.DNSRules) {
}
func (f *fakeDNSRulesAPI) RemoveRestoredDNSRules(_ uint16) {}
