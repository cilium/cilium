/*
   Copyright The ORAS Authors.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package credentials

import (
	"context"
	"sync"

	"oras.land/oras-go/v2/registry/remote/auth"
)

// memoryStore is a store that keeps credentials in memory.
type memoryStore struct {
	store sync.Map
}

// NewMemoryStore creates a new in-memory credentials store.
func NewMemoryStore() Store {
	return &memoryStore{}
}

// Get retrieves credentials from the store for the given server address.
func (ms *memoryStore) Get(_ context.Context, serverAddress string) (auth.Credential, error) {
	cred, found := ms.store.Load(serverAddress)
	if !found {
		return auth.EmptyCredential, nil
	}
	return cred.(auth.Credential), nil
}

// Put saves credentials into the store for the given server address.
func (ms *memoryStore) Put(_ context.Context, serverAddress string, cred auth.Credential) error {
	ms.store.Store(serverAddress, cred)
	return nil
}

// Delete removes credentials from the store for the given server address.
func (ms *memoryStore) Delete(_ context.Context, serverAddress string) error {
	ms.store.Delete(serverAddress)
	return nil
}
