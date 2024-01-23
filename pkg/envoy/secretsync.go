// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	"context"
	"errors"
	"fmt"

	envoy_config_core_v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	envoy_entensions_tls_v3 "github.com/cilium/proxy/go/envoy/extensions/transport_sockets/tls/v3"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	tlsCrtAttribute = "tls.crt"
	tlsKeyAttribute = "tls.key"

	// Key for CA certificate is fixed as 'ca.crt' even though is not as "standard"
	// as 'tls.crt' and 'tls.key' are via k8s tls secret type.
	caCrtAttribute = "ca.crt"
)

// secretSyncer is responsible to sync K8s TLS Secrets in pre-defined namespaces
// via xDS SDS to Envoy.
type secretSyncer struct {
	logger         logrus.FieldLogger
	envoyXdsServer XDSServer
}

func newSecretSyncer(logger logrus.FieldLogger, envoyXdsServer XDSServer) *secretSyncer {
	return &secretSyncer{
		logger:         logger,
		envoyXdsServer: envoyXdsServer,
	}
}

func (r *secretSyncer) handleSecretEvent(ctx context.Context, event resource.Event[*slim_corev1.Secret]) error {
	scopedLogger := r.logger.
		WithField(logfields.K8sNamespace, event.Key.Namespace).
		WithField("name", event.Key.Name)

	var err error

	switch event.Kind {
	case resource.Upsert:
		scopedLogger.Debug("Received Secret upsert event")
		err = r.upsertK8sSecretV1(ctx, event.Object)
		if err != nil {
			scopedLogger.WithError(err).Error("failed to handle Secret upsert")
			err = fmt.Errorf("failed to handle CEC upsert: %w", err)
		}
	case resource.Delete:
		scopedLogger.Debug("Received Secret delete event")
		err = r.deleteK8sSecretV1(ctx, event.Key)
		if err != nil {
			scopedLogger.WithError(err).Error("failed to handle Secret delete")
			err = fmt.Errorf("failed to handle Secret delete: %w", err)
		}
	}

	event.Done(err)

	return err
}

// updateK8sSecretV1 performs Envoy upsert operation for added or updated secret.
func (r *secretSyncer) upsertK8sSecretV1(ctx context.Context, secret *slim_corev1.Secret) error {
	if secret == nil {
		return errors.New("secret is nil")
	}

	resource := Resources{
		Secrets: []*envoy_entensions_tls_v3.Secret{k8sToEnvoySecret(secret)},
	}
	return r.envoyXdsServer.UpsertEnvoyResources(ctx, resource)
}

// deleteK8sSecretV1 makes sure the related secret values in Envoy SDS is removed.
func (r *secretSyncer) deleteK8sSecretV1(ctx context.Context, key resource.Key) error {
	if len(key.Namespace) == 0 || len(key.Name) == 0 {
		return errors.New("key has empty namespace and/or name")
	}

	resource := Resources{
		Secrets: []*envoy_entensions_tls_v3.Secret{
			{
				// For deletion, only the name is required.
				Name: getEnvoySecretName(key.Namespace, key.Name),
			},
		},
	}
	return r.envoyXdsServer.DeleteEnvoyResources(ctx, resource)
}

// k8sToEnvoySecret converts k8s secret object to envoy TLS secret object
func k8sToEnvoySecret(secret *slim_corev1.Secret) *envoy_entensions_tls_v3.Secret {
	if secret == nil {
		return nil
	}
	envoySecret := &envoy_entensions_tls_v3.Secret{
		Name: getEnvoySecretName(secret.GetNamespace(), secret.GetName()),
	}

	if len(secret.Data[tlsCrtAttribute]) > 0 || len(secret.Data[tlsKeyAttribute]) > 0 {
		envoySecret.Type = &envoy_entensions_tls_v3.Secret_TlsCertificate{
			TlsCertificate: &envoy_entensions_tls_v3.TlsCertificate{
				CertificateChain: &envoy_config_core_v3.DataSource{
					Specifier: &envoy_config_core_v3.DataSource_InlineBytes{
						InlineBytes: secret.Data[tlsCrtAttribute],
					},
				},
				PrivateKey: &envoy_config_core_v3.DataSource{
					Specifier: &envoy_config_core_v3.DataSource_InlineBytes{
						InlineBytes: secret.Data[tlsKeyAttribute],
					},
				},
			},
		}
	} else if len(secret.Data[caCrtAttribute]) > 0 {
		envoySecret.Type = &envoy_entensions_tls_v3.Secret_ValidationContext{
			ValidationContext: &envoy_entensions_tls_v3.CertificateValidationContext{
				TrustedCa: &envoy_config_core_v3.DataSource{
					Specifier: &envoy_config_core_v3.DataSource_InlineBytes{
						InlineBytes: secret.Data[caCrtAttribute],
					},
				},
				// TODO: Consider support for other ValidationContext config.
			},
		}
	}

	return envoySecret
}

func getEnvoySecretName(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}
