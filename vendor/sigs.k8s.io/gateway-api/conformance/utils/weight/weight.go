/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package weight

import (
	"cmp"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

const (
	// MaxTestRetries is the maximum number of times to retry the weight distribution test
	// if it fails due to statistical variance before considering it a real failure
	MaxTestRetries = 10
)

// RequestSender defines an interface for sending requests (HTTP, gRPC, or mesh)
type RequestSender interface {
	SendRequest() (podName string, err error)
}

// extractBackendName extracts the backend name from a pod name by removing deployment and pod hash suffixes
func extractBackendName(podName string) string {
	// Pod names follow the pattern: {backend-name}-{deployment-hash}-{pod-hash}
	// We need to remove the last two dash-separated components
	parts := strings.Split(podName, "-")
	if len(parts) < 3 {
		return podName // fall back to original name if pattern doesn't match
	}
	// Remove last two components (deployment hash and pod hash)
	return strings.Join(parts[:len(parts)-2], "-")
}

// BatchRequestSender defines an interface for sending batch requests
type BatchRequestSender interface {
	SendBatchRequest(count int) ([]string, error)
}

// TestWeightedDistribution tests that requests are distributed according to expected weights
func TestWeightedDistribution(sender RequestSender, expectedWeights map[string]float64) error {
	const (
		concurrentRequests  = 10
		tolerancePercentage = 0.05
		totalRequests       = 500
	)

	var (
		g         errgroup.Group
		seenMutex sync.Mutex
		seen      = make(map[string]float64, len(expectedWeights))
	)

	g.SetLimit(concurrentRequests)
	for i := 0; i < totalRequests; i++ {
		g.Go(func() error {
			podName, err := sender.SendRequest()
			if err != nil {
				return err
			}

			// Extract the backend name from the pod name
			backendName := extractBackendName(podName)

			seenMutex.Lock()
			defer seenMutex.Unlock()

			if _, exists := expectedWeights[backendName]; exists {
				seen[backendName]++
				return nil
			}

			return fmt.Errorf("request was handled by an unexpected pod %q (extracted backend: %q)", podName, backendName)
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("error while sending requests: %w", err)
	}

	// Count how many backends should receive traffic (weight > 0)
	expectedActiveBackends := 0
	for _, weight := range expectedWeights {
		if weight > 0.0 {
			expectedActiveBackends++
		}
	}

	var errs []error
	if len(seen) != expectedActiveBackends {
		errs = append(errs, fmt.Errorf("expected %d backends to receive traffic, but got %d", expectedActiveBackends, len(seen)))
	}

	for wantBackend, wantPercent := range expectedWeights {
		gotCount, ok := seen[wantBackend]

		if !ok && wantPercent != 0.0 {
			errs = append(errs, fmt.Errorf("expect traffic to hit backend %q - but none was received", wantBackend))
			continue
		}

		gotPercent := gotCount / float64(totalRequests)

		if math.Abs(gotPercent-wantPercent) > tolerancePercentage {
			errs = append(errs, fmt.Errorf("backend %q weighted traffic of %v not within tolerance %v (+/-%f)",
				wantBackend,
				gotPercent,
				wantPercent,
				tolerancePercentage,
			))
		}
	}

	slices.SortFunc(errs, func(a, b error) int {
		return cmp.Compare(a.Error(), b.Error())
	})
	return errors.Join(errs...)
}

// TestWeightedDistributionBatch tests that requests are distributed according to expected weights
// using batch request execution for improved performance
func TestWeightedDistributionBatch(sender BatchRequestSender, expectedWeights map[string]float64) error {
	const (
		tolerancePercentage = 0.05
		totalRequests       = 500
	)

	// Execute all requests in a single batch
	podNames, err := sender.SendBatchRequest(totalRequests)
	if err != nil {
		return fmt.Errorf("error while sending batch request: %w", err)
	}

	if len(podNames) != totalRequests {
		return fmt.Errorf("expected %d responses but got %d", totalRequests, len(podNames))
	}

	// Count the distribution
	seen := make(map[string]float64, len(expectedWeights))
	for _, podName := range podNames {
		backendName := extractBackendName(podName)

		if _, exists := expectedWeights[backendName]; exists {
			seen[backendName]++
		} else {
			return fmt.Errorf("request was handled by an unexpected pod %q (extracted backend: %q)", podName, backendName)
		}
	}

	// Count how many backends should receive traffic (weight > 0)
	expectedActiveBackends := 0
	for _, weight := range expectedWeights {
		if weight > 0.0 {
			expectedActiveBackends++
		}
	}

	var errs []error
	if len(seen) != expectedActiveBackends {
		errs = append(errs, fmt.Errorf("expected %d backends to receive traffic, but got %d", expectedActiveBackends, len(seen)))
	}

	for wantBackend, wantPercent := range expectedWeights {
		gotCount, ok := seen[wantBackend]

		if !ok && wantPercent != 0.0 {
			errs = append(errs, fmt.Errorf("expect traffic to hit backend %q - but none was received", wantBackend))
			continue
		}

		gotPercent := gotCount / float64(totalRequests)

		if math.Abs(gotPercent-wantPercent) > tolerancePercentage {
			errs = append(errs, fmt.Errorf("backend %q weighted traffic of %v not within tolerance %v (+/-%f)",
				wantBackend,
				gotPercent,
				wantPercent,
				tolerancePercentage,
			))
		}
	}

	slices.SortFunc(errs, func(a, b error) int {
		return cmp.Compare(a.Error(), b.Error())
	})
	return errors.Join(errs...)
}

// Entropy utilities

// addRandomDelay adds a random delay up to the specified limit in milliseconds
func addRandomDelay(limit int) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(limit)))
	if err != nil {
		// Fallback to no delay if crypto/rand fails
		return
	}
	randomSleepDuration := n.Int64()
	time.Sleep(time.Duration(randomSleepDuration) * time.Millisecond)
}

// AddRandomEntropy randomly chooses to add delay, random value, or both
// The addRandomValue function should be provided by the caller to handle
// protocol-specific ways of adding the random value (HTTP headers, gRPC metadata, etc.)
func AddRandomEntropy(addRandomValue func(string) error) error {
	n, err := rand.Int(rand.Reader, big.NewInt(3))
	if err != nil {
		// Fallback to case 0 if crypto/rand fails
		addRandomDelay(1000)
		return err
	}
	random := n.Int64()

	switch random {
	case 0:
		addRandomDelay(1000)
		return nil
	case 1:
		valueN, err := rand.Int(rand.Reader, big.NewInt(10000))
		if err != nil {
			return fmt.Errorf("failed to generate random value: %w", err)
		}
		randomValue := valueN.Int64()
		return addRandomValue(strconv.FormatInt(randomValue, 10))
	case 2:
		addRandomDelay(1000)
		valueN, err := rand.Int(rand.Reader, big.NewInt(10000))
		if err != nil {
			return fmt.Errorf("failed to generate random value: %w", err)
		}
		randomValue := valueN.Int64()
		return addRandomValue(strconv.FormatInt(randomValue, 10))
	default:
		return fmt.Errorf("invalid random value: %d", random)
	}
}
