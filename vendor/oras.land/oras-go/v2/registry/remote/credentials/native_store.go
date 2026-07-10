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
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"

	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials/internal/executer"
)

const (
	remoteCredentialsPrefix       = "docker-credential-"
	emptyUsername                 = "<token>"
	errCredentialsNotFoundMessage = "credentials not found in native keychain"
)

// dockerCredentials mimics how docker credential helper binaries store
// credential information.
// Reference:
//   - https://docs.docker.com/engine/reference/commandline/login/#credential-helper-protocol
type dockerCredentials struct {
	ServerURL string `json:"ServerURL"`
	Username  string `json:"Username"`
	Secret    string `json:"Secret"`
}

// nativeStore implements a credentials store using native keychain to keep
// credentials secure.
type nativeStore struct {
	exec executer.Executer
}

// NewNativeStore creates a new native store that uses a remote helper program to
// manage credentials.
//
// The argument of NewNativeStore can be the native keychains
// ("wincred" for Windows, "pass" for linux and "osxkeychain" for macOS),
// or any program that follows the docker-credentials-helper protocol.
//
// Reference:
//   - https://docs.docker.com/engine/reference/commandline/login#credentials-store
func NewNativeStore(helperSuffix string) Store {
	return &nativeStore{
		exec: executer.New(remoteCredentialsPrefix + helperSuffix),
	}
}

// NewDefaultNativeStore returns a native store based on the platform-default
// docker credentials helper and a bool indicating if the native store is
// available.
//   - Windows: "wincred"
//   - Linux: "pass" or "secretservice"
//   - macOS: "osxkeychain"
//
// Reference:
//   - https://docs.docker.com/engine/reference/commandline/login/#credentials-store
func NewDefaultNativeStore() (Store, bool) {
	if helper := getDefaultHelperSuffix(); helper != "" {
		return NewNativeStore(helper), true
	}
	return nil, false
}

// Get retrieves credentials from the store for the given server.
func (ns *nativeStore) Get(ctx context.Context, serverAddress string) (auth.Credential, error) {
	var cred auth.Credential
	out, err := ns.exec.Execute(ctx, strings.NewReader(serverAddress), "get")
	if err != nil {
		if err.Error() == errCredentialsNotFoundMessage {
			// do not return an error if the credentials are not in the keychain.
			return auth.EmptyCredential, nil
		}
		return auth.EmptyCredential, err
	}
	var dockerCred dockerCredentials
	if err := json.Unmarshal(out, &dockerCred); err != nil {
		return auth.EmptyCredential, err
	}
	// bearer auth is used if the username is "<token>"
	if dockerCred.Username == emptyUsername {
		cred.RefreshToken = dockerCred.Secret
	} else {
		cred.Username = dockerCred.Username
		cred.Password = dockerCred.Secret
	}
	return cred, nil
}

// Put saves credentials into the store.
func (ns *nativeStore) Put(ctx context.Context, serverAddress string, cred auth.Credential) error {
	dockerCred := &dockerCredentials{
		ServerURL: serverAddress,
		Username:  cred.Username,
		Secret:    cred.Password,
	}
	if cred.RefreshToken != "" {
		dockerCred.Username = emptyUsername
		dockerCred.Secret = cred.RefreshToken
	}
	credJSON, err := json.Marshal(dockerCred)
	if err != nil {
		return err
	}
	_, err = ns.exec.Execute(ctx, bytes.NewReader(credJSON), "store")
	return err
}

// Delete removes credentials from the store for the given server.
func (ns *nativeStore) Delete(ctx context.Context, serverAddress string) error {
	_, err := ns.exec.Execute(ctx, strings.NewReader(serverAddress), "erase")
	return err
}

// getDefaultHelperSuffix returns the default credential helper suffix.
func getDefaultHelperSuffix() string {
	platformDefault := getPlatformDefaultHelperSuffix()
	if _, err := exec.LookPath(remoteCredentialsPrefix + platformDefault); err == nil {
		return platformDefault
	}
	return ""
}
