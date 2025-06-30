// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certificatemanager

import (
	"context"
	"errors"

	"github.com/cilium/cilium/pkg/policy/api"
)

func NewMockSecretManagerInline() SecretManager {
	return &mockSecretManager{
		inlineValue: "somevalue",
	}
}

func NewMockSecretManagerNotFound() SecretManager {
	return &mockSecretManager{
		inlineError: errors.New("not found"),
	}
}

func NewMockSecretManagerSDS() SecretManager {
	return &mockSecretManager{
		isSDS: true,
	}
}

type mockSecretManager struct {
	inlineValue string
	inlineError error
	isSDS       bool
}

func (m mockSecretManager) GetSecretString(_ context.Context, secret *api.Secret, ns string) (string, error) {
	return m.inlineValue, m.inlineError
}

func (m mockSecretManager) PolicySecretSyncEnabled() bool {
	return m.isSDS
}

func (m mockSecretManager) SecretsOnlyFromSecretsNamespace() bool {
	return m.isSDS
}

func (m mockSecretManager) GetSecretSyncNamespace() string {
	return ""
}
