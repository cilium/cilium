// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package modules

import (
	"errors"
	"io"
)

var ErrNotImplemented = errors.New("not implemented")

func listModules() ([]string, error) {
	return nil, ErrNotImplemented
}

func moduleLoader() string {
	return "unknown-module-loader"
}

func parseModulesFile(r io.Reader) ([]string, error) {
	return nil, ErrNotImplemented
}
