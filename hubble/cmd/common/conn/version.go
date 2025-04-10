// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package conn

import (
	"log/slog"

	"github.com/blang/semver/v4"
	"google.golang.org/grpc/metadata"

	"github.com/cilium/cilium/hubble/pkg"
	serverdefaults "github.com/cilium/cilium/pkg/hubble/defaults"
	relaydefaults "github.com/cilium/cilium/pkg/hubble/relay/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	// cliVersionComparator allows comparing a semver version to the Hubble CLI version
	// that ignores version parts lower than Minor (Patch/Pre/Build).
	cliVersionComparator = newMinorVersionComparator(pkg.SemverVersion)

	// zeroVersion is used as sentinel value when a version could not be parsed using semver.
	zeroVersion = semver.Version{}
)

// logVersionMismatch returns an onReceiveHeader func that emits a warning log when the Hubble CLI
// version is lower than the remote server version (Hubble server or Hubble relay). We ignore
// Patch/Pre/Build parts of the semver version as these should only contain backward-compatible
// fixes.
func logVersionMismatch() onReceiveHeader {
	return func(log *slog.Logger, header metadata.MD) {
		relayVersion, err := parseVersionFromHeader(header, relaydefaults.GRPCMetadataRelayVersionKey)
		if err != nil {
			log.Debug("Could not parse relay version from grpc headers", logfields.Error, err)
		}
		serverVersion, err := parseVersionFromHeader(header, serverdefaults.GRPCMetadataServerVersionKey)
		if err != nil {
			log.Debug("Could not parse server version from grpc headers", logfields.Error, err)
		}

		if cliVersionComparator.IsLowerThan(relayVersion) {
			log.Warn("Hubble CLI version is lower than Hubble Relay, API compatibility is not guaranteed, updating to a matching or higher version is recommended",
				logfields.HubbleCLIVersion, pkg.SemverVersion.String(),
				logfields.HubbleRelayVersion, relayVersion.String(),
			)
		}

		if cliVersionComparator.IsLowerThan(serverVersion) {
			log.Warn("Hubble CLI version is lower than Hubble Server, API compatibility is not guaranteed, updating to a matching or higher version is recommended",
				logfields.HubbleCLIVersion, pkg.SemverVersion.String(),
				logfields.HubbleServerVersion, serverVersion.String(),
			)
		}
	}
}

type minorVersionComparator struct {
	version semver.Version
}

func newMinorVersionComparator(v semver.Version) *minorVersionComparator {
	return &minorVersionComparator{version: versionTruncateMinor(v)}
}

func (c *minorVersionComparator) IsLowerThan(v semver.Version) bool {
	versionMissing := v.EQ(zeroVersion)
	return !versionMissing && c.version.LT(versionTruncateMinor(v))
}

func versionTruncateMinor(v semver.Version) semver.Version {
	minorV := v
	minorV.Patch = 0
	minorV.Pre = nil
	minorV.Build = nil
	return minorV
}

func parseVersionFromHeader(header metadata.MD, key string) (semver.Version, error) {
	versionHeaders := header.Get(key)
	if len(versionHeaders) == 0 {
		return zeroVersion, nil
	}
	return semver.ParseTolerant(versionHeaders[0])
}
