// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"

	"github.com/google/renameio/v2"

	"github.com/cilium/cilium/pkg/command/exec"
)

func manifestPath(output string) string { return output + ".manifest" }

// inputsDigest hashes the hashProducer digest, the compile arguments and the source they preprocess to.
func inputsDigest(ctx context.Context, logger *slog.Logger, libDir string, args []string) (string, error) {
	producer, err := hashProducer(ctx, logger, libDir)
	if err != nil {
		return "", err
	}
	source, err := exec.CommandContext(ctx, compiler,
		append([]string{"-Wno-unused-command-line-argument", "-E", "-dD"}, args...)...).Output(logger, false)
	if err != nil {
		return "", fmt.Errorf("preprocessing: %w", err)
	}
	h := sha256.New()
	_, _ = h.Write(producer)
	fmt.Fprintf(h, "%q\n", args)
	_, _ = h.Write(source)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// manifestMatches reports whether the manifest records digest for the object now at output.
func manifestMatches(output, digest string) bool {
	data, err := os.ReadFile(manifestPath(output))
	if err != nil {
		return false
	}
	object, err := hashFile(output)
	return err == nil && string(data) == digest+" "+object
}

// writeManifest records that clang built output from the inputs digest describes.
func writeManifest(output, digest string) error {
	object, err := hashFile(output)
	if err != nil {
		return err
	}
	return renameio.WriteFile(manifestPath(output), []byte(digest+" "+object), 0o600)
}
