// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package certificatemanager

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/policy/api"
)

var Cell = cell.Module(
	"certificate-manager",
	"Provides TLS certificates and secrets",

	cell.Provide(NewManager),

	cell.Config(defaultManagerConfig),
)

type CertificateManager interface {
	GetTLSContext(ctx context.Context, tlsCtx *api.TLSContext, ns string) (ca, public, private string, fromFile bool, err error)
}

type SecretManager interface {
	GetSecrets(ctx context.Context, secret *api.Secret, ns string) (string, map[string][]byte, bool, error)
	GetSecretString(ctx context.Context, secret *api.Secret, ns string) (string, error)
	SetSecretSyncNamespace(ns string)
}

var defaultManagerConfig = managerConfig{
	CertificatesDirectory: "/var/run/cilium/certs",
}

type managerConfig struct {
	// CertificatesDirectory is the root directory to be used by cilium to find
	// certificates locally.
	CertificatesDirectory string
}

func (mc managerConfig) Flags(flags *pflag.FlagSet) {
	flags.String("certificates-directory", mc.CertificatesDirectory, "Root directory to find certificates specified in L7 TLS policy enforcement")
}

// Manager will manage the way certificates are retrieved based in the given
// k8sClient and rootPath.
type manager struct {
	rootPath            string
	k8sClient           k8sClient.Clientset
	secretSyncNamespace string
	Logger              logrus.FieldLogger
}

// NewManager returns a new manager.
func NewManager(cfg managerConfig, clientset k8sClient.Clientset, logger logrus.FieldLogger) (CertificateManager, SecretManager) {
	m := &manager{
		rootPath:  cfg.CertificatesDirectory,
		k8sClient: clientset,
		Logger:    logger,
	}

	m.Logger.Debug("certificate-manager starting")

	return m, m
}

// SetSecretSyncNamespace sets the configured secret synchronization namespace.
// Not calling this will disable using secret synchronization, and means that the agent must have
// read access to the secrets used in policy directly.
// Secret Synchronization config includes granting access to the policy-secrets-namespace, configured
// in the envoy Cell.
func (m *manager) SetSecretSyncNamespace(ns string) {
	m.secretSyncNamespace = ns
}

// GetSecrets returns either local or k8s secrets, giving precedence for local secrets if configured.
// It also returns a boolean indicating if the values were read from disk or not.
// The 'ns' parameter is used as the secret namespace if 'secret.Namespace' is an empty string, and is
// expected to be set as the same namespace as the source object (most likely a CNP or CCNP).
func (m *manager) GetSecrets(ctx context.Context, secret *api.Secret, ns string) (string, map[string][]byte, bool, error) {
	if secret == nil {
		return "", nil, false, fmt.Errorf("Secret must not be nil")
	}

	if secret.Namespace != "" {
		ns = secret.Namespace
	}

	if secret.Name == "" {
		return ns, nil, false, fmt.Errorf("Missing Secret name")
	}
	nsName := filepath.Join(ns, secret.Name)

	// Give priority to local secrets.
	// K8s API request is only done if the local secret directory can't be read!
	certPath := filepath.Join(m.rootPath, nsName)
	files, ioErr := os.ReadDir(certPath)
	if ioErr == nil {
		secrets := make(map[string][]byte, len(files))
		for _, file := range files {
			var bytes []byte

			path := filepath.Join(certPath, file.Name())
			bytes, ioErr = os.ReadFile(path)
			if ioErr == nil {
				secrets[file.Name()] = bytes
			}
		}
		// Return the (latest) error only if no secrets were found
		if len(secrets) == 0 && ioErr != nil {
			// Files read from disk, so bool returnval is true
			return nsName, nil, true, ioErr
		}
		// Files read from disk, so bool returnval is true
		return nsName, secrets, true, nil
	}

	// If the secret is _not_ being read from the filesystem, then we don't want to inspect it at all, because
	// that will require the agent to have more access than it needs. So we return an empty `secrets` map.
	// The plan here is to deprecate reading from file entirely, at which all this code will be removed.
	// TODO(youngnick): Deprecate and remove reading from file for secrets.
	emptySecrets := make(map[string][]byte)
	return nsName, emptySecrets, false, nil
}

const (
	caDefaultName      = "ca.crt"
	publicDefaultName  = "tls.crt"
	privateDefaultName = "tls.key"
)

// GetTLSContext returns a new ca, public and private certificates found based
// in the given api.TLSContext.
func (m *manager) GetTLSContext(ctx context.Context, tlsCtx *api.TLSContext, ns string) (ca, public, private string, fromFile bool, err error) {
	name, secrets, fromFile, err := m.GetSecrets(ctx, tlsCtx.Secret, ns)
	if err != nil {
		return "", "", "", false, err
	}

	// If the certificate hasn't been read from a file, we're going to be inserting a reference to an SDS secret instead,
	// so we don't need to validate the values. Envoy will handle validation.
	if !fromFile {
		m.Logger.WithField("secret", name).Debug("Secret being read from Kubernetes")
		return "", "", "", fromFile, nil
	}

	caName := caDefaultName
	if tlsCtx.TrustedCA != "" {
		caName = tlsCtx.TrustedCA
	}
	caBytes, ok := secrets[caName]
	if ok {
		ca = string(caBytes)
	} else if tlsCtx.TrustedCA != "" {
		return "", "", "", false, fmt.Errorf("Trusted CA %s not found in secret %s", caName, name)
	}

	publicName := publicDefaultName
	if tlsCtx.Certificate != "" {
		publicName = tlsCtx.Certificate
	}
	publicBytes, ok := secrets[publicName]
	if ok {
		public = string(publicBytes)
	} else if tlsCtx.Certificate != "" {
		return "", "", "", false, fmt.Errorf("Certificate %s not found in secret %s", publicName, name)
	}

	privateName := privateDefaultName
	if tlsCtx.PrivateKey != "" {
		privateName = tlsCtx.PrivateKey
	}
	privateBytes, ok := secrets[privateName]
	if ok {
		private = string(privateBytes)
	} else if tlsCtx.PrivateKey != "" {
		return "", "", "", false, fmt.Errorf("Private Key %s not found in secret %s", privateName, name)
	}

	if caBytes == nil && publicBytes == nil && privateBytes == nil {
		return "", "", "", false, fmt.Errorf("TLS certificates not found in secret %s ", name)
	}

	// TODO(youngnick): Follow up PR that will change this to a deprecation warning once we actually
	// mark read-from-file as deprecated.
	m.Logger.WithField("secret", name).Debug("Secret read from file")
	return ca, public, private, fromFile, nil
}

// GetSecretString returns a secret string stored in a k8s secret
func (m *manager) GetSecretString(ctx context.Context, secret *api.Secret, ns string) (string, error) {
	// TODO: Update this and to handle read-from-file
	name, secrets, _, err := m.GetSecrets(ctx, secret, ns)
	if err != nil {
		return "", err
	}

	if len(secrets) == 1 {
		// get the lone item by looping into the map
		for _, value := range secrets {
			return string(value), nil
		}
	}
	return "", fmt.Errorf("Secret %s must have exactly one item", name)
}
