// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestGenerateL7RulesByParser(t *testing.T) {
	m := generateL7AllowAllRules(ParserTypeHTTP, "", "")
	require.Nil(t, m)

	m = generateL7AllowAllRules(ParserTypeKafka, "", "")
	require.Nil(t, m)

	m = generateL7AllowAllRules(ParserTypeDNS, "ns-name", "pod-name")
	require.NotNil(t, m)
	require.Equal(t, 1, len(m))

	for k, v := range m {
		// Check that we allow all at L7 for DNS for the one rule we should have
		// generated.
		require.EqualValues(t, &PerSelectorPolicy{L7Rules: api.L7Rules{DNS: []api.PortRuleDNS{{MatchPattern: "*"}}}}, v)

		require.EqualValues(t, labels.LabelArray{
			labels.NewLabel(ciliumio.PolicyLabelDerivedFrom, "PodVisibilityAnnotation", labels.LabelSourceK8s),
			labels.NewLabel(ciliumio.PodNamespaceLabel, "ns-name", labels.LabelSourceK8s),
			labels.NewLabel(ciliumio.PodNameLabel, "pod-name", labels.LabelSourceK8s),
		}, k.GetMetadataLabels())
	}

	// test that we are not setting empty metadata labels when provided pod or namespace name is empty
	m = generateL7AllowAllRules(ParserTypeDNS, "ns-name", "")

	for k := range m {
		require.EqualValues(t, labels.LabelArray{
			labels.NewLabel(ciliumio.PolicyLabelDerivedFrom, "PodVisibilityAnnotation", labels.LabelSourceK8s),
			labels.NewLabel(ciliumio.PodNamespaceLabel, "ns-name", labels.LabelSourceK8s),
		}, k.GetMetadataLabels())
	}

	m = generateL7AllowAllRules(ParserTypeDNS, "", "pod-name")

	for k := range m {
		require.EqualValues(t, labels.LabelArray{
			labels.NewLabel(ciliumio.PolicyLabelDerivedFrom, "PodVisibilityAnnotation", labels.LabelSourceK8s),
			labels.NewLabel(ciliumio.PodNameLabel, "pod-name", labels.LabelSourceK8s),
		}, k.GetMetadataLabels())
	}

	m = generateL7AllowAllRules(ParserTypeDNS, "", "")

	for k := range m {
		require.EqualValues(t, labels.LabelArray{
			labels.NewLabel(ciliumio.PolicyLabelDerivedFrom, "PodVisibilityAnnotation", labels.LabelSourceK8s),
		}, k.GetMetadataLabels())
	}
}

func TestVisibilityPolicyCreation(t *testing.T) {

	anno := "<Ingress/80/TCP/HTTP>"
	vp, err := NewVisibilityPolicy(anno, "", "")
	require.NotNil(t, vp)
	require.NoError(t, err)

	require.Equal(t, 1, len(vp.Ingress))
	require.Equal(t, &VisibilityMetadata{
		Proto:   u8proto.TCP,
		Port:    uint16(80),
		Parser:  ParserTypeHTTP,
		Ingress: true,
	}, vp.Ingress["80/TCP"])

	anno = "<Ingress/80/TCP/HTTP>,<Ingress/8080/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno, "", "")
	require.NotNil(t, vp)
	require.NoError(t, err)

	require.Equal(t, 2, len(vp.Ingress))
	require.Equal(t, &VisibilityMetadata{
		Proto:   u8proto.TCP,
		Port:    uint16(80),
		Parser:  ParserTypeHTTP,
		Ingress: true,
	}, vp.Ingress["80/TCP"])
	require.Equal(t, &VisibilityMetadata{
		Proto:   u8proto.TCP,
		Port:    uint16(8080),
		Parser:  ParserTypeHTTP,
		Ingress: true,
	}, vp.Ingress["8080/TCP"])

	anno = "<Ingress/80/TCP/HTTP>,<Ingress/80/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno, "", "")
	require.NotNil(t, vp)
	require.NoError(t, err)

	require.Equal(t, 1, len(vp.Ingress))
	require.Equal(t, &VisibilityMetadata{
		Proto:   u8proto.TCP,
		Port:    uint16(80),
		Parser:  ParserTypeHTTP,
		Ingress: true,
	}, vp.Ingress["80/TCP"])

	anno = "<Ingress/80/TCP/HTTP>,<Ingress/80/TCP/Kafka>"
	vp, err = NewVisibilityPolicy(anno, "", "")
	require.Nil(t, vp)
	require.NotNil(t, err)

	anno = "asdf"
	vp, err = NewVisibilityPolicy(anno, "", "")
	require.Nil(t, vp)
	require.NotNil(t, err)

	anno = "<Ingress/65536/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno, "", "")
	require.Nil(t, vp)
	require.NotNil(t, err)

	anno = "<Ingress/65535/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno, "", "")
	require.NotNil(t, vp)
	require.NoError(t, err)

	anno = "<Ingress/99999/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno, "", "")
	require.Nil(t, vp)
	require.NotNil(t, err)

	anno = "<Ingress/0/TCP/HTTP>"
	vp, err = NewVisibilityPolicy(anno, "", "")
	require.Nil(t, vp)
	require.NotNil(t, err)

	// Do not allow > 5 digits.
	anno = "<Ingress/123456/TCP/HTTP"
	vp, err = NewVisibilityPolicy(anno, "", "")
	require.Nil(t, vp)
	require.NotNil(t, err)

	// Do not allow leading zeroes.
	anno = "<Ingress/02345/TCP/HTTP"
	vp, err = NewVisibilityPolicy(anno, "", "")
	require.Nil(t, vp)
	require.NotNil(t, err)

	anno = "<Egress/53/ANY/DNS>"
	vp, err = NewVisibilityPolicy(anno, "", "")
	require.NoError(t, err)
	require.Equal(t, 3, len(vp.Egress))
	udp, ok := vp.Egress["53/UDP"]
	require.True(t, ok)
	require.Equal(t, u8proto.UDP, udp.Proto)
	tcp, ok := vp.Egress["53/TCP"]
	require.Equal(t, u8proto.TCP, tcp.Proto)
	require.True(t, ok)
	sctp, ok := vp.Egress["53/SCTP"]
	require.Equal(t, u8proto.SCTP, sctp.Proto)
	require.True(t, ok)

}
