// Copyright 2019 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package api

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GetGroupName(t *testing.T) {
	assert.NoError(t, os.Setenv(HubbleGroupNameKey, "mygroup"))
	assert.Equal(t, GetGroupName(), "mygroup")
	assert.NoError(t, os.Unsetenv(HubbleGroupNameKey))
	assert.Equal(t, GetGroupName(), HubbleGroupName)
}

func Test_GetDefaultSocketPath(t *testing.T) {
	assert.NoError(t, os.Setenv(DefaultSocketPathKey, "unix:///socket/path"))
	assert.Equal(t, GetDefaultSocketPath(), "unix:///socket/path")
	assert.NoError(t, os.Unsetenv(DefaultSocketPathKey))
	assert.Equal(t, GetDefaultSocketPath(), DefaultSocketPath)
}
