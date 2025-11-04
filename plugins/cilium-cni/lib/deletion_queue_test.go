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
	errorCaseTwice
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
	case errorCaseTwice:
		if e.callCount <= 2 {
			return e.err
		}
		return nil
	case errorCaseAlways:
		return e.err
	default:
		return nil
	}
}

type fakeCiliumClient struct {
	errorMock
}

func (f *fakeCiliumClient) EndpointDeleteMany(_ *models.EndpointBatchDeleteRequest) error {
	return f.call()
}

type fakeCiliumClientCreator struct {
	errorMock

	clientErrorMock errorMock
}

func (f *fakeCiliumClientCreator) ToString() string {
	errMockStrs := []string{"Never", "Once", "Twice", "Always"}

	return fmt.Sprintf("NewClient: %s, EndpointDelete: %s",
		errMockStrs[f.errorMock.errorCase],
		errMockStrs[f.clientErrorMock.errorCase])
}

func (f *fakeCiliumClientCreator) newClient(_ time.Duration) (ciliumClient, error) {
	err := f.call()
	if err != nil {
		return nil, err
	}

	return &fakeCiliumClient{f.clientErrorMock}, nil
}

func TestDeletionFallbackClient(t *testing.T) {
	logger := hivetest.Logger(t)

	newDeletionClient := func(newClientFn newCiliumClientFn, testDir string) DeletionFallbackClient {
		deleteQueueLockfile := path.Join(testDir, "lockfile")
		return DeletionFallbackClient{
			logger: logger,

			deleteQueueDir:      testDir,
			deleteQueueLockfile: deleteQueueLockfile,

			newCiliumClientFn: newClientFn,
			connectionBackoff: time.Millisecond,
		}
	}

	newClientErr := errors.New("error creating cilium client")
	newClientErrorNever := errorMock{
		errorCase: errorCaseNever,
	}
	newClientErrorOnce := errorMock{
		errorCase: errorCaseOnce,
		err:       newClientErr,
	}
	newClientErrorAlways := errorMock{
		errorCase: errorCaseAlways,
		err:       newClientErr,
	}

	deletionClientErr := &endpoint.DeleteEndpointServiceUnavailable{}
	deletionClientErrorNever := errorMock{
		errorCase: errorCaseNever,
	}
	deletionClientErrorOnce := errorMock{
		errorCase: errorCaseOnce,
		err:       deletionClientErr,
	}
	deletionClientErrorTwice := errorMock{
		errorCase: errorCaseTwice,
		err:       deletionClientErr,
	}
	deletionClientErrorAlways := errorMock{
		errorCase: errorCaseAlways,
		err:       deletionClientErr,
	}

	tt := []struct {
		newClientCreator    fakeCiliumClientCreator
		shouldQueueDeletion bool
	}{
		{
			newClientCreator: fakeCiliumClientCreator{
				errorMock:       newClientErrorNever,
				clientErrorMock: deletionClientErrorNever,
			},
			shouldQueueDeletion: false,
		},
		{
			newClientCreator: fakeCiliumClientCreator{
				errorMock:       newClientErrorNever,
				clientErrorMock: deletionClientErrorOnce,
			},
			shouldQueueDeletion: false,
		},
		{
			newClientCreator: fakeCiliumClientCreator{
				errorMock:       newClientErrorNever,
				clientErrorMock: deletionClientErrorAlways,
			},
			shouldQueueDeletion: true,
		},
		{
			newClientCreator: fakeCiliumClientCreator{
				errorMock:       newClientErrorOnce,
				clientErrorMock: deletionClientErrorNever,
			},
			shouldQueueDeletion: false,
		},
		{
			newClientCreator: fakeCiliumClientCreator{
				errorMock:       newClientErrorOnce,
				clientErrorMock: deletionClientErrorOnce,
			},
			shouldQueueDeletion: true,
		},
		{
			newClientCreator: fakeCiliumClientCreator{
				errorMock:       newClientErrorOnce,
				clientErrorMock: deletionClientErrorTwice,
			},
			shouldQueueDeletion: true,
		},
		{
			newClientCreator: fakeCiliumClientCreator{
				errorMock:       newClientErrorOnce,
				clientErrorMock: deletionClientErrorAlways,
			},
			shouldQueueDeletion: true,
		},
		{
			newClientCreator: fakeCiliumClientCreator{
				errorMock:       newClientErrorAlways,
				clientErrorMock: deletionClientErrorNever,
			},
			shouldQueueDeletion: true,
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
		testName := tc.newClientCreator.ToString()

		t.Run(testName, func(t *testing.T) {
			testDir := t.TempDir()

			dc := newDeletionClient(tc.newClientCreator.newClient, testDir)

			err = dc.EndpointDeleteMany(deleteReq)
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
