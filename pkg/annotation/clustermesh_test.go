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
	require.Equal(t, ServiceAffinityLocal, GetAnnotationServiceAffinity(obj))

	obj = &object{
		Annotations: map[string]string{GlobalService: "true", ServiceAffinity: "remote"},
	}
	require.Equal(t, ServiceAffinityRemote, GetAnnotationServiceAffinity(obj))

	obj = &object{
		Annotations: map[string]string{GlobalService: "true", ServiceAffinityAlias: "local"},
	}
	require.Equal(t, ServiceAffinityLocal, GetAnnotationServiceAffinity(obj))

	obj = &object{
		Annotations: map[string]string{ServiceAffinity: "remote"},
	}
	require.Equal(t, ServiceAffinityNone, GetAnnotationServiceAffinity(obj))

	obj = &object{
		Annotations: map[string]string{},
	}
	require.Equal(t, ServiceAffinityNone, GetAnnotationServiceAffinity(obj))
}
