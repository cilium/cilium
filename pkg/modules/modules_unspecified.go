// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

// +build !linux

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
