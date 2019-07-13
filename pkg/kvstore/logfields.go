// Copyright 2016-2018 Authors of Cilium
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

package kvstore

import (
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "kvstore")

const (
	// fieldKVStoreModule is the name of the kvstore backend (etcd or consul)
	fieldKVStoreModule = "module"

	// name of watcher
	fieldWatcher = "watcher"

	// key revision
	fieldRev = "revision"

	// fieldSession refers to a connection/session with the kvstore
	fieldSession = "session"

	// fieldPrefix is the prefix of the key used in the operation
	fieldPrefix = "prefix"

	// fieldKey is the prefix of the key used in the operation
	fieldKey = "key"

	// fieldValue is the prefix of the key used in the operation
	fieldValue = "value"

	// fieldCondition is the condition that requires to be met
	fieldCondition = "condition"

	// fieldNumEntries is the number of entries in the result
	fieldNumEntries = "numEntries"

	// fieldAttachLease is true if the key must be attached to a lease
	fieldAttachLease = "attachLease"

	// fieldEtcdEndpoint is the etcd endpoint we talk to
	fieldEtcdEndpoint = "etcdEndpoint"
)
