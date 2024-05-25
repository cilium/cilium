// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConcurrentLogger(t *testing.T) {
	// prepare test message templates
	testMessages := []string{"start %s"}
	for i := 1; i <= 50; i++ {
		testMessages = append(testMessages, "running-"+strconv.Itoa(i)+" %s")
	}
	testMessages = append(testMessages, "finish %s")

	tests := []struct {
		name        string
		concurrency int
		testCount   int
	}{
		{
			name:        "sequential run",
			concurrency: 1,
			testCount:   100,
		},
		{
			name:        "concurrent run [2x50]",
			concurrency: 2,
			testCount:   50,
		},
		{
			name:        "concurrent run [10x50]",
			concurrency: 10,
			testCount:   50,
		},
		{
			name:        "concurrent run [30x50]",
			concurrency: 30,
			testCount:   50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logBuf := &bytes.Buffer{}
			logger := NewConcurrentLogger(logBuf, tt.concurrency)
			logger.Start(context.Background())

			connTests := make([]*ConnectivityTest, 0, tt.concurrency)
			wg := &sync.WaitGroup{}
			for i := 0; i < tt.concurrency; i++ {
				connTests = append(connTests, &ConnectivityTest{
					params: Parameters{TestNamespace: fmt.Sprintf("namespace-%d", i)},
					logger: logger,
				})
				wg.Add(1)
				go func(ct *ConnectivityTest) {
					defer wg.Done()
					// simulate tests run for the ConnectivityTest instance
					for j := 0; j < tt.testCount; j++ {
						test := &Test{
							ctx:  ct,
							name: fmt.Sprintf("test-%d", j),
						}
						// print test messages
						for _, m := range testMessages {
							logger.Printf(test, m+"\n", fmt.Sprintf("%s:%s", test.ctx.params.TestNamespace, test.name))
						}
						logger.FinishTest(test)
					}
				}(connTests[i])
			}
			wg.Wait()
			logger.Stop()

			logLines := strings.Split(logBuf.String(), "\n")
			// remove last empty line
			logLines = logLines[:len(logLines)-1]

			// assert log lines count
			expectedLogLines := tt.concurrency * tt.testCount * len(testMessages)
			require.Equal(t, expectedLogLines, len(logLines))

			// assert test message order and total count
			uniqueTests := make(map[string]struct{})
			for i := 0; i < len(logLines); {
				require.True(t, strings.HasPrefix(logLines[i], "start "))
				name := strings.TrimPrefix(logLines[i], "start ")
				for _, m := range testMessages {
					require.Equal(t, fmt.Sprintf(m, name), logLines[i])
					i++
				}
				uniqueTests[name] = struct{}{}
			}

			// assert unique test count
			expectedTestCount := tt.concurrency * tt.testCount
			require.Equal(t, expectedTestCount, len(uniqueTests))
		})
	}
}
