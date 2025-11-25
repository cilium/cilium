// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build cover

package coverage

import (
	"net/http"
	"os"
	"runtime/coverage"
	"sync"
	"time"
)

type coverageMiddleware struct {
	next        http.Handler
	lastFlush   time.Time
	flushMutex  sync.Mutex
	minInterval time.Duration
	coverageDir string
}

func NewCoverageMiddleware(next http.Handler) http.Handler {
	coverageDir := os.Getenv("GOCOVERDIR")
	if coverageDir == "" {
		return next
	}

	return &coverageMiddleware{
		next:        next,
		minInterval: 5 * time.Second,
		coverageDir: coverageDir,
	}
}

func (m *coverageMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Serve the request first
	m.next.ServeHTTP(w, r)

	// Try to flush coverage after the request
	m.tryFlushCoverage()
}

func (m *coverageMiddleware) tryFlushCoverage() {
	m.flushMutex.Lock()
	defer m.flushMutex.Unlock()

	now := time.Now()
	if now.Sub(m.lastFlush) < m.minInterval {
		// Too soon since last flush, skip
		return
	}

	coverage.WriteCountersDir(m.coverageDir)

	coverage.WriteMetaDir(m.coverageDir)

	m.lastFlush = now
}
