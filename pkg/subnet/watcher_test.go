// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subnet

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	subnetTable "github.com/cilium/cilium/pkg/maps/subnet"
)

func TestDecodeJson(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []subnetTable.SubnetTableEntry
		wantErr  bool
	}{
		{
			name:     "empty string",
			input:    "",
			expected: []subnetTable.SubnetTableEntry{},
			wantErr:  false,
		},
		{
			name:     "whitespace only",
			input:    "   ",
			expected: []subnetTable.SubnetTableEntry{},
			wantErr:  false,
		},
		{
			name:  "single CIDR",
			input: "10.0.0.0/24",
			expected: []subnetTable.SubnetTableEntry{
				subnetTable.NewSubnetEntry(netip.MustParsePrefix("10.0.0.0/24"), 1),
			},
			wantErr: false,
		},
		{
			name:  "two CIDRs in same group",
			input: "10.0.0.0/24,10.10.0.0/24",
			expected: []subnetTable.SubnetTableEntry{
				subnetTable.NewSubnetEntry(netip.MustParsePrefix("10.0.0.0/24"), 1),
				subnetTable.NewSubnetEntry(netip.MustParsePrefix("10.10.0.0/24"), 1),
			},
			wantErr: false,
		},
		{
			name:  "two groups with semicolon separator",
			input: "10.0.0.0/24;10.20.0.0/24",
			expected: []subnetTable.SubnetTableEntry{
				subnetTable.NewSubnetEntry(netip.MustParsePrefix("10.0.0.0/24"), 1),
				subnetTable.NewSubnetEntry(netip.MustParsePrefix("10.20.0.0/24"), 2),
			},
			wantErr: false,
		},
		{
			name:  "complex topology from CFP example",
			input: "10.0.0.1/24,10.10.0.1/24;10.20.0.1/24;2001:0db8:85a3::/64",
			expected: []subnetTable.SubnetTableEntry{
				subnetTable.NewSubnetEntry(netip.MustParsePrefix("10.0.0.1/24"), 1),
				subnetTable.NewSubnetEntry(netip.MustParsePrefix("10.10.0.1/24"), 1),
				subnetTable.NewSubnetEntry(netip.MustParsePrefix("10.20.0.1/24"), 2),
				subnetTable.NewSubnetEntry(netip.MustParsePrefix("2001:db8:85a3::/64"), 3),
			},
			wantErr: false,
		},
		{
			name:  "topology with whitespace",
			input: " 10.0.0.0/24 , 10.10.0.0/24 ; 10.20.0.0/24 ",
			expected: []subnetTable.SubnetTableEntry{
				subnetTable.NewSubnetEntry(netip.MustParsePrefix("10.0.0.0/24"), 1),
				subnetTable.NewSubnetEntry(netip.MustParsePrefix("10.10.0.0/24"), 1),
				subnetTable.NewSubnetEntry(netip.MustParsePrefix("10.20.0.0/24"), 2),
			},
			wantErr: false,
		},
		{
			name:    "invalid CIDR",
			input:   "not-a-cidr",
			wantErr: true,
		},
		{
			name:    "partially invalid - one bad CIDR",
			input:   "10.0.0.0/24,invalid",
			wantErr: true,
		},
		{
			name:  "ipv6 only",
			input: "2001:db8::/32,fd00::/8",
			expected: []subnetTable.SubnetTableEntry{
				subnetTable.NewSubnetEntry(netip.MustParsePrefix("2001:db8::/32"), 1),
				subnetTable.NewSubnetEntry(netip.MustParsePrefix("fd00::/8"), 1),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := decodeJson(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Len(t, result, len(tt.expected))
			for i, entry := range result {
				assert.Equal(t, tt.expected[i].Key, entry.Key, "entry %d key mismatch", i)
				assert.Equal(t, tt.expected[i].Value, entry.Value, "entry %d value (group ID) mismatch", i)
			}
		})
	}
}

func TestDecodeJsonGroupIDs(t *testing.T) {
	// Verify that group IDs are assigned sequentially starting from 1
	// and that CIDRs within the same group share the same ID.
	result, err := decodeJson("10.0.0.0/24,10.1.0.0/24;10.2.0.0/24;10.3.0.0/24,10.4.0.0/24")
	require.NoError(t, err)
	require.Len(t, result, 5)

	// Group 1: IDs should be 1
	assert.Equal(t, uint32(1), result[0].Value, "10.0.0.0/24 should have group ID 1")
	assert.Equal(t, uint32(1), result[1].Value, "10.1.0.0/24 should have group ID 1")

	// Group 2: ID should be 2
	assert.Equal(t, uint32(2), result[2].Value, "10.2.0.0/24 should have group ID 2")

	// Group 3: IDs should be 3
	assert.Equal(t, uint32(3), result[3].Value, "10.3.0.0/24 should have group ID 3")
	assert.Equal(t, uint32(3), result[4].Value, "10.4.0.0/24 should have group ID 3")
}

// TestCloseOnceChannelPattern verifies that the select-based close-once pattern
// used in registerSubnetWatcher does not panic on repeated iterations.
func TestCloseOnceChannelPattern(t *testing.T) {
	synced := make(chan struct{})

	for i := 0; i < 10; i++ {
		select {
		case <-synced:
			// Channel already closed, nothing to do 
		default:
			// Channel is still open, only happens on first iteration
			close(synced)
		}
	}

	// Verify the channel is closed by confirming a read succeeds without blocking
	select {
	case <-synced:
	default:
		t.Fatal("expected channel to be closed")
	}
}
