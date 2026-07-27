// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package names

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
)

const (
	syncedSecretPrefix    = "cilium-sync-secret-"
	syncedConfigMapPrefix = "cilium-sync-cfgmap-"
)

// SyncedSecretName returns the name of the Secret copy for a source Secret.
func SyncedSecretName(source types.NamespacedName) string {
	return syncedName(syncedSecretPrefix, "secret", source)
}

// SyncedConfigMapSecretName returns the name of the Secret copy for a source ConfigMap.
func SyncedConfigMapSecretName(source types.NamespacedName) string {
	return syncedName(syncedConfigMapPrefix, "configmap", source)
}

// SyncedSDSSecretName returns the SDS resource name for a synchronized Secret.
func SyncedSDSSecretName(secretsNamespace string, source types.NamespacedName) string {
	if secretsNamespace == "" {
		return SourceSDSSecretName(source)
	}
	return fmt.Sprintf("%s/%s", secretsNamespace, SyncedSecretName(source))
}

// SyncedConfigMapSDSSecretName returns the SDS resource name for a synchronized ConfigMap.
func SyncedConfigMapSDSSecretName(secretsNamespace string, source types.NamespacedName) string {
	if secretsNamespace == "" {
		return SourceSDSSecretName(source)
	}
	return fmt.Sprintf("%s/%s", secretsNamespace, SyncedConfigMapSecretName(source))
}

// SourceSDSSecretName returns the SDS resource name for a Secret consumed from its source namespace.
func SourceSDSSecretName(source types.NamespacedName) string {
	return fmt.Sprintf("%s/%s", source.Namespace, source.Name)
}

// LegacySyncedSecretName returns the pre-hash synced Secret name.
func LegacySyncedSecretName(source types.NamespacedName) string {
	return source.Namespace + "-" + source.Name
}

// LegacySyncedConfigMapSecretName returns the pre-hash synced ConfigMap Secret name.
func LegacySyncedConfigMapSecretName(source types.NamespacedName) string {
	return source.Namespace + "-cfgmap-" + source.Name
}

func syncedName(prefix, kind string, source types.NamespacedName) string {
	digest := sha256.Sum256([]byte(kind + "\x00" + source.Namespace + "\x00" + source.Name))
	return prefix + hex.EncodeToString(digest[:])
}
