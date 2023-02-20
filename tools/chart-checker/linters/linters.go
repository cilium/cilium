// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linters

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os/exec"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
)

type Linter interface {
	Lint(chartPath string, values []string) error
	Name() string
	Description() string
}

var Linters = []Linter{
	&PreFlightLinter{},
}

const (
	DefaultNamespace   = "test-cilium-namespace"
	PlaceholderVersion = "99.99.0"
)

// render renders a given template + set of values
// just shells out to helm, rather than implementing it in go
func render(name, chartPath string, values []string) ([]*unstructured.Unstructured, error) {
	_, err := exec.LookPath("helm")
	if err != nil {
		return nil, fmt.Errorf("could not find helm binary, please install: %w", err)
	}

	sets := make([]string, 0, 2*len(values))
	for _, v := range values {
		sets = append(sets, "--set", v)
	}

	cmd := exec.Command("helm", "template",
		"--namespace", DefaultNamespace,
		name, chartPath,
		"--version", PlaceholderVersion,
	)
	cmd.Args = append(cmd.Args, sets...)
	log.Println(cmd.Args)

	out, err := cmd.Output()
	if err != nil {
		if err, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("failed to execute %v: %s %w", cmd.Args, err.Stderr, err)
		}
		return nil, fmt.Errorf("failed to execute %v: %w", cmd.Args, err)
	}

	return parseManifests(out)
}

func parseManifests(in []byte) ([]*unstructured.Unstructured, error) {
	out := []*unstructured.Unstructured{}

	buf := bytes.NewBuffer(in)
	decoder := yaml.NewYAMLOrJSONDecoder(buf, 4096)
	for {
		u := unstructured.Unstructured{}
		if err := decoder.Decode(&u); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to parse manifest as k8s object: %w", err)
		}
		if u.GetKind() == "" { // The YAML decoder saw an empty file
			continue
		}
		out = append(out, &u)
	}
	log.Printf("got %d objects", len(out))

	return out, nil
}
