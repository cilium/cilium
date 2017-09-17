// Copyright 2016 The etcd Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"bytes"
	"sort"

	"github.com/coreos/etcd/auth/authpb"
	"github.com/coreos/etcd/mvcc/backend"
)

// isSubset returns true if a is a subset of b.
// If a is a prefix of b, then a is a subset of b.
// Given intervals [a1,a2) and [b1,b2), is
// the a interval a subset of b?
func isSubset(a, b *rangePerm) bool {
	switch {
	case len(a.end) == 0 && len(b.end) == 0:
		// a, b are both keys
		return bytes.Equal(a.begin, b.begin)
	case len(b.end) == 0:
		// b is a key, a is a range
		return false
	case len(a.end) == 0:
		// a is a key, b is a range. need b1 <= a1 and a1 < b2
		return bytes.Compare(b.begin, a.begin) <= 0 && bytes.Compare(a.begin, b.end) < 0
	default:
		// both are ranges. need b1 <= a1 and a2 <= b2
		return bytes.Compare(b.begin, a.begin) <= 0 && bytes.Compare(a.end, b.end) <= 0
	}
}

func isRangeEqual(a, b *rangePerm) bool {
	return bytes.Equal(a.begin, b.begin) && bytes.Equal(a.end, b.end)
}

// removeSubsetRangePerms removes any rangePerms that are subsets of other rangePerms.
// If there are equal ranges, removeSubsetRangePerms only keeps one of them.
// It returns a sorted rangePerm slice.
func removeSubsetRangePerms(perms []*rangePerm) (newp []*rangePerm) {
	sort.Sort(RangePermSliceByBegin(perms))
	var prev *rangePerm
	for i := range perms {
		if i == 0 {
			prev = perms[i]
			newp = append(newp, perms[i])
			continue
		}
		if isRangeEqual(perms[i], prev) {
			continue
		}
		if isSubset(perms[i], prev) {
			continue
		}
		if isSubset(prev, perms[i]) {
			prev = perms[i]
			newp[len(newp)-1] = perms[i]
			continue
		}
		prev = perms[i]
		newp = append(newp, perms[i])
	}
	return newp
}

// mergeRangePerms merges adjacent rangePerms.
func mergeRangePerms(perms []*rangePerm) []*rangePerm {
	var merged []*rangePerm
	perms = removeSubsetRangePerms(perms)

	i := 0
	for i < len(perms) {
		begin, next := i, i
		for next+1 < len(perms) && bytes.Compare(perms[next].end, perms[next+1].begin) >= 0 {
			next++
		}
		// don't merge ["a", "b") with ["b", ""), because perms[next+1].end is empty.
		if next != begin && len(perms[next].end) > 0 {
			merged = append(merged, &rangePerm{begin: perms[begin].begin, end: perms[next].end})
		} else {
			merged = append(merged, perms[begin])
			if next != begin {
				merged = append(merged, perms[next])
			}
		}
		i = next + 1
	}

	return merged
}

func getMergedPerms(tx backend.BatchTx, userName string) *unifiedRangePermissions {
	user := getUser(tx, userName)
	if user == nil {
		plog.Errorf("invalid user name %s", userName)
		return nil
	}

	var readPerms, writePerms []*rangePerm

	for _, roleName := range user.Roles {
		role := getRole(tx, roleName)
		if role == nil {
			continue
		}

		for _, perm := range role.KeyPermission {
			rp := &rangePerm{begin: perm.Key, end: perm.RangeEnd}

			switch perm.PermType {
			case authpb.READWRITE:
				readPerms = append(readPerms, rp)
				writePerms = append(writePerms, rp)

			case authpb.READ:
				readPerms = append(readPerms, rp)

			case authpb.WRITE:
				writePerms = append(writePerms, rp)
			}
		}
	}

	return &unifiedRangePermissions{
		readPerms:  mergeRangePerms(readPerms),
		writePerms: mergeRangePerms(writePerms),
	}
}

func checkKeyPerm(cachedPerms *unifiedRangePermissions, key, rangeEnd []byte, permtyp authpb.Permission_Type) bool {
	var tocheck []*rangePerm

	switch permtyp {
	case authpb.READ:
		tocheck = cachedPerms.readPerms
	case authpb.WRITE:
		tocheck = cachedPerms.writePerms
	default:
		plog.Panicf("unknown auth type: %v", permtyp)
	}

	requiredPerm := &rangePerm{begin: key, end: rangeEnd}

	for _, perm := range tocheck {
		if isSubset(requiredPerm, perm) {
			return true
		}
	}

	return false
}

func (as *authStore) isRangeOpPermitted(tx backend.BatchTx, userName string, key, rangeEnd []byte, permtyp authpb.Permission_Type) bool {
	// assumption: tx is Lock()ed
	_, ok := as.rangePermCache[userName]
	if !ok {
		perms := getMergedPerms(tx, userName)
		if perms == nil {
			plog.Errorf("failed to create a unified permission of user %s", userName)
			return false
		}
		as.rangePermCache[userName] = perms
	}

	return checkKeyPerm(as.rangePermCache[userName], key, rangeEnd, permtyp)
}

func (as *authStore) clearCachedPerm() {
	as.rangePermCache = make(map[string]*unifiedRangePermissions)
}

func (as *authStore) invalidateCachedPerm(userName string) {
	delete(as.rangePermCache, userName)
}

type unifiedRangePermissions struct {
	// readPerms[i] and readPerms[j] (i != j) don't overlap
	readPerms []*rangePerm
	// writePerms[i] and writePerms[j] (i != j) don't overlap, too
	writePerms []*rangePerm
}

type rangePerm struct {
	begin, end []byte
}

type RangePermSliceByBegin []*rangePerm

func (slice RangePermSliceByBegin) Len() int {
	return len(slice)
}

func (slice RangePermSliceByBegin) Less(i, j int) bool {
	switch bytes.Compare(slice[i].begin, slice[j].begin) {
	case 0: // begin(i) == begin(j)
		return bytes.Compare(slice[i].end, slice[j].end) == -1

	case -1: // begin(i) < begin(j)
		return true

	default:
		return false
	}
}

func (slice RangePermSliceByBegin) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}
