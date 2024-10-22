// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"fmt"
	"math/rand"
)

// Adjective generates a random adjective.
func Adjective() string {
	return adjectives[rand.Intn(len(adjectives))]
}

// AlphaNum generates a random alphanumeric string of the given length.
func AlphaNum(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = alphanum[rand.Intn(len(alphanum))]
	}
	return string(b)
}

// App generates a random software application name.
func App() string {
	return apps[rand.Intn(len(apps))]
}

// Noun generates a random noun.
func Noun() string {
	return nouns[rand.Intn(len(nouns))]
}

// Name generates a random name.
func Name() string {
	return fmt.Sprintf("%s_%s", Adjective(), Noun())
}

// Names generates a random set of names. It panics if max < 0.
func Names(max int) []string {
	n := rand.Intn(max + 1)
	names := make([]string, n)
	for i := 0; i < n; i++ {
		names[i] = Name()
	}
	return names
}

// DeploymentTier generates a random software deployment tier such as prod,
// staging, etc.
func DeploymentTier() string {
	return tiers[rand.Intn(len(tiers))]
}
