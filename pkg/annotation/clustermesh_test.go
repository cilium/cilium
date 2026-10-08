// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package annotation

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetAnnotationIncludeExternal(t *testing.T) {
	obj := &object{}
	require.False(t, GetAnnotationIncludeExternal(obj))

	obj = &object{
		Annotations: map[string]string{GlobalService: "True"},
	}
	require.True(t, GetAnnotationIncludeExternal(obj))

	obj = &object{
		Annotations: map[string]string{GlobalService: "false"},
	}
	require.False(t, GetAnnotationIncludeExternal(obj))

	obj = &object{
		Annotations: map[string]string{GlobalService: ""},
	}
	require.False(t, GetAnnotationIncludeExternal(obj))

	obj = &object{
		Annotations: map[string]string{GlobalServiceAlias: "True"},
	}
	require.True(t, GetAnnotationIncludeExternal(obj))
}

func TestGetAnnotationShared(t *testing.T) {
	obj := &object{}
	require.False(t, GetAnnotationShared(obj))
	obj = &object{
		Annotations: map[string]string{GlobalService: "true"},
	}
	require.True(t, GetAnnotationShared(obj))

	obj = &object{
		Annotations: map[string]string{SharedService: "true"},
	}
	require.False(t, GetAnnotationShared(obj))

	obj = &object{
		Annotations: map[string]string{GlobalService: "true", SharedService: "True"},
	}
	require.True(t, GetAnnotationShared(obj))

	obj = &object{
		Annotations: map[string]string{GlobalService: "true", SharedService: "false"},
	}
	require.False(t, GetAnnotationShared(obj))

	obj = &object{
		Annotations: map[string]string{GlobalService: "true", SharedServiceAlias: "false"},
	}
	require.False(t, GetAnnotationShared(obj))
}

func TestGetAnnotationServiceAffinity(t *testing.T) {
	obj := &object{
		Annotations: map[string]string{GlobalService: "true", ServiceAffinity: "local"},
	}
	affinity, err := GetAnnotationServiceAffinity(obj)
	require.NoError(t, err)
	require.Equal(t, ServiceAffinityLocal, affinity)

	obj = &object{
		Annotations: map[string]string{GlobalService: "true", ServiceAffinity: "remote"},
	}
	affinity, err = GetAnnotationServiceAffinity(obj)
	require.NoError(t, err)
	require.Equal(t, ServiceAffinityRemote, affinity)

	obj = &object{
		Annotations: map[string]string{GlobalService: "true", ServiceAffinityAlias: "local"},
	}
	affinity, err = GetAnnotationServiceAffinity(obj)
	require.NoError(t, err)
	require.Equal(t, ServiceAffinityLocal, affinity)

	obj = &object{
		Annotations: map[string]string{ServiceAffinity: "remote"},
	}
	affinity, err = GetAnnotationServiceAffinity(obj)
	require.NoError(t, err)
	require.Equal(t, ServiceAffinityNone, affinity)

	obj = &object{
		Annotations: map[string]string{},
	}
	affinity, err = GetAnnotationServiceAffinity(obj)
	require.NoError(t, err)
	require.Equal(t, ServiceAffinityNone, affinity)

	obj = &object{
		Annotations: map[string]string{GlobalService: "true", ServiceAffinity: "none"},
	}
	affinity, err = GetAnnotationServiceAffinity(obj)
	require.NoError(t, err)
	require.Equal(t, ServiceAffinityNone, affinity)

	obj = &object{
		Annotations: map[string]string{GlobalService: "true", ServiceAffinity: "invalid_value"},
	}
	affinity, err = GetAnnotationServiceAffinity(obj)
	require.Error(t, err)
	require.Equal(t, ServiceAffinityNone, affinity)
}
