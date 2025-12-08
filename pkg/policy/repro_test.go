package policy

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	cilium "github.com/cilium/proxy/go/cilium/api"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/identity"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

func TestRangeToMapState(t *testing.T) {
	logger := slog.Default()
	epPolicy := NewEndpointPolicy(logger, &dummyRepo{})

	// Filter covering port 80-82
	// 80 (0x50) - 82 (0x52)
	// Expected masks:
	// 80/15 (covers 80, 81)
	// 82/16 (covers 82)
	l4 := &L4Filter{
		Port:     80,
		EndPort:  82,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		Ingress:  true,
		PerSelectorPolicies: L7DataMap{
			&testCachedSelector{name: "wildcard", wildcard: true}: nil,
		},
		wildcard: &testCachedSelector{name: "wildcard", wildcard: true},
	}

	l4.toMapState(logger, epPolicy, 0, ChangeState{})

	// Check policyMapState size
	// Expecting 2 entries (one for each masked port)
	// If EndPort is ignored/zero, we get 1 entry (80/16)
	require.Equal(t, 2, epPolicy.policyMapState.Len())
}

type dummyRepo struct{}

func (d *dummyRepo) BumpRevision() uint64                                              { return 0 }
func (d *dummyRepo) GetAuthTypes(localID, remoteID identity.NumericIdentity) AuthTypes { return nil }
func (d *dummyRepo) GetEnvoyHTTPRules(*api.L7Rules, string) (*cilium.HttpNetworkPolicyRules, bool) {
	return nil, false
}
func (d *dummyRepo) GetSelectorPolicy(*identity.Identity, uint64, GetPolicyStatistics, uint64) (SelectorPolicy, uint64, error) {
	return nil, 0, nil
}
func (d *dummyRepo) GetPolicySnapshot() map[identity.NumericIdentity]SelectorPolicy { return nil }
func (d *dummyRepo) GetRevision() uint64                                            { return 0 }
func (d *dummyRepo) GetRulesList() *models.Policy                                   { return nil }
func (d *dummyRepo) GetSelectorCache() *SelectorCache                               { return nil }
func (d *dummyRepo) Iterate(f func(rule *types.PolicyEntry))                        {}
func (d *dummyRepo) ReplaceByResource(rules types.PolicyEntries, resource ipcachetypes.ResourceID) (*set.Set[identity.NumericIdentity], uint64, int) {
	return nil, 0, 0
}
func (d *dummyRepo) Search() (types.PolicyEntries, uint64) { return nil, 0 }
