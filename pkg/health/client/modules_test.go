// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/health/client"
	"github.com/cilium/cilium/pkg/hive/health/types"
)

func TestGetAndFormatModulesHealth(t *testing.T) {
	uu := map[string]struct {
		ss []types.Status
		e  string
		v  bool
	}{
		"happy": {
			e: "Stopped(0) Degraded(2) OK(2)",
		},
		"happy-verbose": {
			e: `agent
		├── a
		│   └── b
		│       └── c
		│           ├── dork                                            [DEGRADED] doh (n/a, x0)
		│           └── fred
		│               ├── [reporter]                                  [OK] yo (n/a, x0)
		│               └── blee                                        [DEGRADED] bozo (n/a, x0)
		└── m1
		    └── foo                                                     [OK] status nominal (n/a, x0)`,
			v: true,
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			w := bytes.NewBufferString("")
			client.GetAndFormatModulesHealth(w, getHealth(), u.v, "\t\t")
			assert.Equal(t, u.e, strings.TrimSpace(w.String()))
		})
	}
}

// Helpers

func ident(mid []string, cid ...string) types.Identifier {
	return types.Identifier{
		Module:    mid,
		Component: cid,
	}
}

func getHealth() []types.Status {
	return []types.Status{
		{
			ID:      ident([]string{"agent", "m1"}, "foo"),
			Level:   types.LevelOK,
			Message: "status nominal",
		},
		{
			ID:      ident([]string{"agent", "a.b.c"}, "fred"),
			Level:   types.LevelOK,
			Message: "yo",
		},
		{
			ID:      ident([]string{"agent", "a.b.c"}, "fred", "blee"),
			Level:   types.LevelDegraded,
			Message: "bozo",
		},
		{
			ID:      ident([]string{"agent", "a.b.c"}, "dork"),
			Level:   types.LevelDegraded,
			Message: "doh",
		},
	}
}
