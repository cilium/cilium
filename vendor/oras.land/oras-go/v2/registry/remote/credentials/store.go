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

// Package credentials supports reading, saving, and removing credentials from
// Docker configuration files and external credential stores that follow
// the Docker credential helper protocol.
//
// Reference: https://docs.docker.com/engine/reference/commandline/login/#credential-stores
package credentials

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"oras.land/oras-go/v2/internal/syncutil"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials/internal/config"
)

const (
	dockerConfigDirEnv   = "DOCKER_CONFIG"
	dockerConfigFileDir  = ".docker"
	dockerConfigFileName = "config.json"
)

// Store is the interface that any credentials store must implement.
type Store interface {
	// Get retrieves credentials from the store for the given server address.
	Get(ctx context.Context, serverAddress string) (auth.Credential, error)
	// Put saves credentials into the store for the given server address.
	Put(ctx context.Context, serverAddress string, cred auth.Credential) error
	// Delete removes credentials from the store for the given server address.
	Delete(ctx context.Context, serverAddress string) error
}

// DynamicStore dynamically determines which store to use based on the settings
// in the config file.
type DynamicStore struct {
	config             *config.Config
	options            StoreOptions
	detectedCredsStore string
	setCredsStoreOnce  syncutil.OnceOrRetry
}

// StoreOptions provides options for NewStore.
type StoreOptions struct {
	// AllowPlaintextPut allows saving credentials in plaintext in the config
	// file.
	//   - If AllowPlaintextPut is set to false (default value), Put() will
	//     return an error when native store is not available.
	//   - If AllowPlaintextPut is set to true, Put() will save credentials in
	//     plaintext in the config file when native store is not available.
	AllowPlaintextPut bool

	// DetectDefaultNativeStore enables detecting the platform-default native
	// credentials store when the config file has no authentication information.
	//
	// If DetectDefaultNativeStore is set to true, the store will detect and set
	// the default native credentials store in the "credsStore" field of the
	// config file.
	//   - Windows: "wincred"
	//   - Linux: "pass" or "secretservice"
	//   - macOS: "osxkeychain"
	//
	// References:
	//   - https://docs.docker.com/engine/reference/commandline/login/#credentials-store
	//   - https://docs.docker.com/engine/reference/commandline/cli/#docker-cli-configuration-file-configjson-properties
	DetectDefaultNativeStore bool
}

// NewStore returns a Store based on the given configuration file.
//
// For Get(), Put() and Delete(), the returned Store will dynamically determine
// which underlying credentials store to use for the given server address.
// The underlying credentials store is determined in the following order:
//  1. Native server-specific credential helper
//  2. Native credentials store
//  3. The plain-text config file itself
//
// References:
//   - https://docs.docker.com/engine/reference/commandline/login/#credentials-store
//   - https://docs.docker.com/engine/reference/commandline/cli/#docker-cli-configuration-file-configjson-properties
func NewStore(configPath string, opts StoreOptions) (*DynamicStore, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	ds := &DynamicStore{
		config:  cfg,
		options: opts,
	}
	if opts.DetectDefaultNativeStore && !cfg.IsAuthConfigured() {
		// no authentication configured, detect the default credentials store
		ds.detectedCredsStore = getDefaultHelperSuffix()
	}
	return ds, nil
}

// NewStoreFromDocker returns a Store based on the default docker config file.
//   - If the $DOCKER_CONFIG environment variable is set,
//     $DOCKER_CONFIG/config.json will be used.
//   - Otherwise, the default location $HOME/.docker/config.json will be used.
//
// NewStoreFromDocker internally calls [NewStore].
//
// References:
//   - https://docs.docker.com/engine/reference/commandline/cli/#configuration-files
//   - https://docs.docker.com/engine/reference/commandline/cli/#change-the-docker-directory
func NewStoreFromDocker(opt StoreOptions) (*DynamicStore, error) {
	configPath, err := getDockerConfigPath()
	if err != nil {
		return nil, err
	}
	return NewStore(configPath, opt)
}

// Get retrieves credentials from the store for the given server address.
func (ds *DynamicStore) Get(ctx context.Context, serverAddress string) (auth.Credential, error) {
	return ds.getStore(serverAddress).Get(ctx, serverAddress)
}

// Put saves credentials into the store for the given server address.
// Put returns ErrPlaintextPutDisabled if native store is not available and
// [StoreOptions].AllowPlaintextPut is set to false.
func (ds *DynamicStore) Put(ctx context.Context, serverAddress string, cred auth.Credential) error {
	if err := ds.getStore(serverAddress).Put(ctx, serverAddress, cred); err != nil {
		return err
	}
	// save the detected creds store back to the config file on first put
	return ds.setCredsStoreOnce.Do(func() error {
		if ds.detectedCredsStore != "" {
			if err := ds.config.SetCredentialsStore(ds.detectedCredsStore); err != nil {
				return fmt.Errorf("failed to set credsStore: %w", err)
			}
		}
		return nil
	})
}

// Delete removes credentials from the store for the given server address.
func (ds *DynamicStore) Delete(ctx context.Context, serverAddress string) error {
	return ds.getStore(serverAddress).Delete(ctx, serverAddress)
}

// IsAuthConfigured returns whether there is authentication configured in the
// config file or not.
//
// IsAuthConfigured returns true when:
//   - The "credsStore" field is not empty
//   - Or the "credHelpers" field is not empty
//   - Or there is any entry in the "auths" field
func (ds *DynamicStore) IsAuthConfigured() bool {
	return ds.config.IsAuthConfigured()
}

// ConfigPath returns the path to the config file.
func (ds *DynamicStore) ConfigPath() string {
	return ds.config.Path()
}

// getHelperSuffix returns the credential helper suffix for the given server
// address.
func (ds *DynamicStore) getHelperSuffix(serverAddress string) string {
	// 1. Look for a server-specific credential helper first
	if helper := ds.config.GetCredentialHelper(serverAddress); helper != "" {
		return helper
	}
	// 2. Then look for the configured native store
	if credsStore := ds.config.CredentialsStore(); credsStore != "" {
		return credsStore
	}
	// 3. Use the detected default store
	return ds.detectedCredsStore
}

// getStore returns a store for the given server address.
func (ds *DynamicStore) getStore(serverAddress string) Store {
	if helper := ds.getHelperSuffix(serverAddress); helper != "" {
		return NewNativeStore(helper)
	}

	fs := newFileStore(ds.config)
	fs.DisablePut = !ds.options.AllowPlaintextPut
	return fs
}

// getDockerConfigPath returns the path to the default docker config file.
func getDockerConfigPath() (string, error) {
	// first try the environment variable
	configDir := os.Getenv(dockerConfigDirEnv)
	if configDir == "" {
		// then try home directory
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		configDir = filepath.Join(homeDir, dockerConfigFileDir)
	}
	return filepath.Join(configDir, dockerConfigFileName), nil
}

// storeWithFallbacks is a store that has multiple fallback stores.
type storeWithFallbacks struct {
	stores []Store
}

// NewStoreWithFallbacks returns a new store based on the given stores.
//   - Get() searches the primary and the fallback stores
//     for the credentials and returns when it finds the
//     credentials in any of the stores.
//   - Put() saves the credentials into the primary store.
//   - Delete() deletes the credentials from the primary store.
func NewStoreWithFallbacks(primary Store, fallbacks ...Store) Store {
	if len(fallbacks) == 0 {
		return primary
	}
	return &storeWithFallbacks{
		stores: append([]Store{primary}, fallbacks...),
	}
}

// Get retrieves credentials from the StoreWithFallbacks for the given server.
// It searches the primary and the fallback stores for the credentials of serverAddress
// and returns when it finds the credentials in any of the stores.
func (sf *storeWithFallbacks) Get(ctx context.Context, serverAddress string) (auth.Credential, error) {
	for _, s := range sf.stores {
		cred, err := s.Get(ctx, serverAddress)
		if err != nil {
			return auth.EmptyCredential, err
		}
		if cred != auth.EmptyCredential {
			return cred, nil
		}
	}
	return auth.EmptyCredential, nil
}

// Put saves credentials into the StoreWithFallbacks. It puts
// the credentials into the primary store.
func (sf *storeWithFallbacks) Put(ctx context.Context, serverAddress string, cred auth.Credential) error {
	return sf.stores[0].Put(ctx, serverAddress, cred)
}

// Delete removes credentials from the StoreWithFallbacks for the given server.
// It deletes the credentials from the primary store.
func (sf *storeWithFallbacks) Delete(ctx context.Context, serverAddress string) error {
	return sf.stores[0].Delete(ctx, serverAddress)
}
