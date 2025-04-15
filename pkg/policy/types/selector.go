// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package types

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
)

// CachedSelector represents an identity selector owned by the selector cache
type CachedSelector interface {
	// GetSelections returns the cached set of numeric identities
	// selected by the CachedSelector.  The retuned slice must NOT
	// be modified, as it is shared among multiple users.
	GetSelections(*versioned.VersionHandle) identity.NumericIdentitySlice

	// GetMetadataLabels returns metadata labels for additional context
	// surrounding the selector. These are typically the labels associated with
	// Cilium rules.
	GetMetadataLabels() labels.LabelArray

	// Selects return 'true' if the CachedSelector selects the given
	// numeric identity.
	Selects(*versioned.VersionHandle, identity.NumericIdentity) bool

	// IsWildcard returns true if the endpoint selector selects
	// all endpoints.
	IsWildcard() bool

	// IsNone returns true if the selector never selects anything
	IsNone() bool

	// String returns the string representation of this selector.
	// Used as a map key.
	String() string
}

// CachedSelectorSlice is a slice of CachedSelectors that can be sorted.
type CachedSelectorSlice []CachedSelector

// MarshalJSON returns the CachedSelectors as JSON formatted buffer
func (s CachedSelectorSlice) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString("[")
	for i, selector := range s {
		buf, err := json.Marshal(selector.String())
		if err != nil {
			return nil, err
		}

		buffer.Write(buf)
		if i < len(s)-1 {
			buffer.WriteString(",")
		}
	}
	buffer.WriteString("]")
	return buffer.Bytes(), nil
}

func (s CachedSelectorSlice) Len() int      { return len(s) }
func (s CachedSelectorSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s CachedSelectorSlice) Less(i, j int) bool {
	return strings.Compare(s[i].String(), s[j].String()) < 0
}

// SelectsAllEndpoints returns whether the CachedSelectorSlice selects all
// endpoints, which is true if the wildcard endpoint selector is present in the
// slice.
func (s CachedSelectorSlice) SelectsAllEndpoints() bool {
	for _, selector := range s {
		if selector.IsWildcard() {
			return true
		}
	}
	return false
}

// CachedSelectionUser inserts selectors into the cache and gets update
// callbacks whenever the set of selected numeric identities change for
// the CachedSelectors pushed by it.
// Callbacks are executed from a separate goroutine that does not take the
// selector cache lock, so the implemenations generally may call back to
// the selector cache.
type CachedSelectionUser interface {
	// The caller is responsible for making sure the same identity is not
	// present in both 'added' and 'deleted'.
	IdentitySelectionUpdated(logger *slog.Logger, selector CachedSelector, added, deleted []identity.NumericIdentity)

	// IdentitySelectionCommit tells the user that all IdentitySelectionUpdated calls relating
	// to a specific added or removed identity have been made.
	IdentitySelectionCommit(logger *slog.Logger, txn *versioned.Tx)

	// IsPeerSelector returns true if the selector is used by the policy
	// engine for selecting traffic for remote peers. False if used for
	// selecting policy subjects.
	IsPeerSelector() bool
}
