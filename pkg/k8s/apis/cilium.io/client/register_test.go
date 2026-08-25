// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	operatorOption "github.com/cilium/cilium/operator/option"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/synced"
)

func TestCiliumEnvoyExtProcFilterCRDRegistration(t *testing.T) {
	crdList := CustomResourceDefinitionList()
	crd, ok := crdList[synced.CRDResourceName(v2alpha1.CEEPFName)]
	require.True(t, ok)
	require.Equal(t, CEEPFCRDName, crd.Name)
	require.Equal(t, v2alpha1.CEEPFName, crd.FullName)

	generated := GetPregeneratedCRD(slog.Default(), crd.Name)
	require.Equal(t, v2alpha1.CEEPFName, generated.Name)
	require.Equal(t, v2alpha1.CEEPFKindDefinition, generated.Spec.Names.Kind)
	require.Equal(t, v2alpha1.CEEPFPluralName, generated.Spec.Names.Plural)

	previous := operatorOption.Config.EnableGatewayAPI
	operatorOption.Config.EnableGatewayAPI = true
	t.Cleanup(func() { operatorOption.Config.EnableGatewayAPI = previous })
	require.Contains(t, synced.GatewayAPIResourceNames(), synced.CRDResourceName(v2alpha1.CEEPFName))
}
