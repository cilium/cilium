// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lib

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"path"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/client/endpoint"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/lock/lockfile"
)

type errorCase int

const (
	errorCaseNever errorCase = iota
	errorCaseOnce
	errorCaseAlways
)

type errorMock struct {
	errorCase errorCase
	err       error

	callCount int
}

func (e *errorMock) call() error {
	e.callCount++

	switch e.errorCase {
	case errorCaseNever:
		return nil
	case errorCaseOnce:
		if e.callCount == 1 {
			return e.err
		}
		return nil
	case errorCaseAlways:
		return e.err
	default:
		return nil
	}
}

type fakeCiliumEndpointDeleter struct {
	errorMock
}

func (f *fakeCiliumEndpointDeleter) deleteEndpoint(_ *endpoint.DeleteEndpointParams) error {
	return f.call()
}

func (f *fakeCiliumEndpointDeleter) toString() string {
	return fmt.Sprintf("[Error: %s, ErrorCase: %v]", f.err, f.errorCase)
}

func TestDeletionFallbackClient(t *testing.T) {
	logger := hivetest.Logger(t)

	newDeletionClient := func(testEndpointDeleter endpointDeleter, testDir string) DeletionFallbackClient {
		deleteQueueLockfile := path.Join(testDir, "lockfile")
		return DeletionFallbackClient{
			logger: logger,

			deleteQueueDir:      testDir,
			deleteQueueLockfile: deleteQueueLockfile,

			endpointDeleter: testEndpointDeleter,
		}
	}

	unknownError := errors.New("unknown error")
	tt := []struct {
		endpointDeleter     fakeCiliumEndpointDeleter
		shouldQueueDeletion bool
		shouldFail          bool
	}{
		{
			endpointDeleter: fakeCiliumEndpointDeleter{
				errorMock: errorMock{
					errorCase: errorCaseNever,
					err:       nil,
				},
			},
			shouldQueueDeletion: false,
			shouldFail:          false,
		},
		{
			endpointDeleter: fakeCiliumEndpointDeleter{
				errorMock: errorMock{
					errorCase: errorCaseOnce,
					err:       &endpoint.DeleteEndpointNotFound{},
				},
			},
			shouldQueueDeletion: false,
			shouldFail:          true,
		},
		{
			endpointDeleter: fakeCiliumEndpointDeleter{
				errorMock: errorMock{
					errorCase: errorCaseAlways,
					err:       &endpoint.DeleteEndpointNotFound{},
				},
			},
			shouldQueueDeletion: false,
			shouldFail:          true,
		},
		{
			endpointDeleter: fakeCiliumEndpointDeleter{
				errorMock: errorMock{
					errorCase: errorCaseOnce,
					err:       &endpoint.DeleteEndpointInvalid{},
				},
			},
			shouldQueueDeletion: false,
			shouldFail:          true,
		},
		{
			endpointDeleter: fakeCiliumEndpointDeleter{
				errorMock: errorMock{
					errorCase: errorCaseAlways,
					err:       &endpoint.DeleteEndpointInvalid{},
				},
			},
			shouldQueueDeletion: false,
			shouldFail:          true,
		},
		{
			endpointDeleter: fakeCiliumEndpointDeleter{
				errorMock: errorMock{
					errorCase: errorCaseOnce,
					err:       &endpoint.DeleteEndpointServiceUnavailable{},
				},
			},
			shouldQueueDeletion: false,
			shouldFail:          false,
		},
		{
			endpointDeleter: fakeCiliumEndpointDeleter{
				errorMock: errorMock{
					errorCase: errorCaseAlways,
					err:       &endpoint.DeleteEndpointServiceUnavailable{},
				},
			},
			shouldQueueDeletion: true,
			shouldFail:          false,
		},
		{
			endpointDeleter: fakeCiliumEndpointDeleter{
				errorMock: errorMock{
					errorCase: errorCaseOnce,
					err:       &endpoint.DeleteEndpointTooManyRequests{},
				},
			},
			shouldQueueDeletion: false,
			shouldFail:          false,
		},
		{
			endpointDeleter: fakeCiliumEndpointDeleter{
				errorMock: errorMock{
					errorCase: errorCaseAlways,
					err:       &endpoint.DeleteEndpointTooManyRequests{},
				},
			},
			shouldQueueDeletion: true,
			shouldFail:          false,
		},
		{
			endpointDeleter: fakeCiliumEndpointDeleter{
				errorMock: errorMock{
					errorCase: errorCaseOnce,
					err:       unknownError,
				},
			},
			shouldQueueDeletion: false,
			shouldFail:          false,
		},
		{
			endpointDeleter: fakeCiliumEndpointDeleter{
				errorMock: errorMock{
					errorCase: errorCaseAlways,
					err:       unknownError,
				},
			},
			shouldQueueDeletion: true,
			shouldFail:          false,
		},
	}

	deleteReq := &models.EndpointBatchDeleteRequest{
		ContainerID: "test-container-id",
	}

	contents, err := deleteReq.MarshalBinary()
	require.NoError(t, err)

	h := sha256.New()
	h.Write(contents)
	deleteQueueFilename := fmt.Sprintf("%x.delete", h.Sum(nil))

	for _, tc := range tt {
		testName := tc.endpointDeleter.toString()

		t.Run(testName, func(t *testing.T) {
			testDir := t.TempDir()

			dc := newDeletionClient(tc.endpointDeleter.deleteEndpoint, testDir)

			err = dc.EndpointDeleteMany(deleteReq)
			if tc.shouldFail {
				require.ErrorIs(t, err, tc.endpointDeleter.err)
				return
			}
			require.NoError(t, err)

			deleteQueueFile := path.Join(testDir, deleteQueueFilename)
			if tc.shouldQueueDeletion {
				require.FileExists(t, deleteQueueFile)
			} else {
				require.NoFileExists(t, deleteQueueFile)
			}
		})
	}
}

func acquireExclusiveLock(t *testing.T, lockFile string) (*lockfile.Lockfile, error) {
	t.Helper()

	lf, err := lockfile.NewLockfile(lockFile)
	require.NoError(t, err)
	require.NotNil(t, lf)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = lf.Lock(ctx, true)
	if err != nil {
		return nil, err
	}

	return lf, nil
}

func TestQueueLock(t *testing.T) {
	testDir := t.TempDir()

	lockDir := path.Join(testDir, "deletion_queue")
	lockFile := path.Join(lockDir, "lockfile")

	dc := &DeletionFallbackClient{
		logger:              hivetest.Logger(t),
		deleteQueueDir:      lockDir,
		deleteQueueLockfile: lockFile,
	}

	lf, err := dc.tryQueueLock()
	require.NoError(t, err)
	require.NotNil(t, lf)

	// CNI acquires shared lock.
	lf2, err := dc.tryQueueLock()
	require.NoError(t, err)
	require.NotNil(t, lf2)

	lf3, err := acquireExclusiveLock(t, lockFile)
	require.Error(t, err)
	require.Nil(t, lf3)

	lf.Unlock()
	lf2.Unlock()

	lf3, err = acquireExclusiveLock(t, lockFile)
	require.NoError(t, err)
	require.NotNil(t, lf3)
	lf3.Unlock()
}
