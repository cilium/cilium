// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/proxy/pkg/policy/api/kafka"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/fqdn/re"
)

func setUpSuite(b testing.TB) {
	re.InitRegexCompileLRU(hivetest.Logger(b), defaults.FQDNRegexCompileLRUSize)
}

func TestHTTPEqual(t *testing.T) {
	setUpSuite(t)

	rule1 := PortRuleHTTP{Path: "/foo$", Method: "GET", Headers: []string{"X-Test: Foo"}}
	rule2 := PortRuleHTTP{Path: "/bar$", Method: "GET", Headers: []string{"X-Test: Foo"}}
	rule3 := PortRuleHTTP{Path: "/foo$", Method: "GET", Headers: []string{"X-Test: Bar"}}

	require.True(t, rule1.Equal(rule1))
	require.False(t, rule1.Equal(rule2))
	require.False(t, rule1.Equal(rule3))

	rules := L7Rules{
		HTTP: []PortRuleHTTP{rule1, rule2},
	}

	require.True(t, rule1.Exists(rules))
	require.True(t, rule2.Exists(rules))
	require.False(t, rule3.Exists(rules))
}

func TestHTTPCompare(t *testing.T) {
	setUpSuite(t)

	orderedRules := []PortRuleHTTP{
		{Path: "/bar$", Method: "GET", Headers: []string{"X-Test: Foo"}},
		{Path: "/foo$", Method: "GET", Headers: []string{"X-Test: Bar"}},
		{Path: "/foo$", Method: "GET", Headers: []string{"X-Test: Foo"}},
		{Path: "/foo$", Method: "PUT", HeaderMatches: []*HeaderMatch{
			{Name: "X-Test", Mismatch: MismatchActionAdd, Value: "Bar"},
		}},
		{Path: "/foo$", Method: "PUT", HeaderMatches: []*HeaderMatch{
			{Name: "X-Test", Mismatch: MismatchActionLog, Value: "Bar"},
		}},
		{Path: "/foo$", Method: "PUT", Headers: []string{"X-Test: Bar"}},
	}

	for i, firstRule := range orderedRules {
		for j, secondRule := range orderedRules {
			if i == j {
				require.Zero(t, firstRule.Compare(secondRule), "Expected rule %d == rule %d", i, j)
			} else if i < j {
				require.Negative(t, firstRule.Compare(secondRule), "Expected rule %d < rule %d", i, j)
			} else {
				require.Positive(t, firstRule.Compare(secondRule), "Expected rule %d > rule %d", i, j)
			}
		}
	}
}

func TestSecretEqual(t *testing.T) {
	setUpSuite(t)

	rule1 := &Secret{Namespace: "ns1", Name: "name1"}
	rule2 := &Secret{Namespace: "ns2", Name: "name1"}
	rule3 := &Secret{Namespace: "ns1", Name: "name2"}
	var rule4 *Secret = nil

	require.True(t, rule1.Equal(rule1))
	require.True(t, rule4.Equal(rule4))

	require.False(t, rule1.Equal(rule2))
	require.False(t, rule1.Equal(rule3))
	require.False(t, rule1.Equal(rule4))

	require.False(t, rule2.Equal(rule1))
	require.False(t, rule3.Equal(rule1))
	require.False(t, rule4.Equal(rule1))
}

func TestSecretCompare(t *testing.T) {
	setUpSuite(t)

	orderedRules := []*Secret{
		nil,
		{Namespace: "ns1", Name: "name1"},
		{Namespace: "ns1", Name: "name2"},
		{Namespace: "ns2", Name: "name1"},
		{Namespace: "ns2", Name: "name2"},
	}

	for i, firstRule := range orderedRules {
		for j, secondRule := range orderedRules {
			if i == j {
				require.Zero(t, firstRule.Compare(secondRule), "Expected rule %d == rule %d", i, j)
			} else if i < j {
				require.Negative(t, firstRule.Compare(secondRule), "Expected rule %d < rule %d", i, j)
			} else {
				require.Positive(t, firstRule.Compare(secondRule), "Expected rule %d > rule %d", i, j)
			}
		}
	}

}

func TestHeaderMatchEqual(t *testing.T) {
	setUpSuite(t)

	rule1 := &HeaderMatch{Name: "header1", Value: "value1", Mismatch: MismatchActionLog}
	rule2 := &HeaderMatch{Name: "header2", Value: "value1", Mismatch: MismatchActionLog}
	rule3 := &HeaderMatch{Name: "header1", Value: "value2", Mismatch: MismatchActionLog}
	rule4 := &HeaderMatch{Name: "header1", Value: "value1", Mismatch: MismatchActionAdd}
	rule5 := &HeaderMatch{Name: "header1", Value: "value1", Mismatch: MismatchActionLog,
		Secret: &Secret{Namespace: "ns1", Name: "name1"},
	}

	require.True(t, rule1.Equal(rule1))
	require.True(t, rule2.Equal(rule2))
	require.True(t, rule3.Equal(rule3))
	require.True(t, rule4.Equal(rule4))
	require.True(t, rule5.Equal(rule5))

	require.False(t, rule1.Equal(rule2))
	require.False(t, rule1.Equal(rule3))
	require.False(t, rule1.Equal(rule4))
	require.False(t, rule1.Equal(rule5))

	require.False(t, rule2.Equal(rule1))
	require.False(t, rule3.Equal(rule1))
	require.False(t, rule4.Equal(rule1))
	require.False(t, rule5.Equal(rule1))
}

func TestHeaderMatchCompare(t *testing.T) {
	setUpSuite(t)

	orderedRules := []*HeaderMatch{
		nil,
		{Name: "header2", Value: "value2", Mismatch: MismatchActionAdd},
		{Name: "header1", Value: "value1", Mismatch: MismatchActionLog},
		{Name: "header1", Value: "value2", Mismatch: MismatchActionLog},
		{Name: "header2", Value: "value1", Mismatch: MismatchActionLog},
		{Name: "header2", Value: "value2", Mismatch: MismatchActionLog},
		{Name: "header2", Value: "value2", Mismatch: MismatchActionLog, Secret: &Secret{Namespace: "ns1", Name: "name1"}},
	}

	for i, firstRule := range orderedRules {
		for j, secondRule := range orderedRules {
			if i == j {
				require.Zero(t, firstRule.Compare(secondRule), "Expected rule %d == rule %d", i, j)
			} else if i < j {
				require.Negative(t, firstRule.Compare(secondRule), "Expected rule %d < rule %d", i, j)
			} else {
				require.Positive(t, firstRule.Compare(secondRule), "Expected rule %d > rule %d", i, j)
			}
		}
	}
}

func TestKafkaEqual(t *testing.T) {
	setUpSuite(t)

	rule1 := kafka.PortRule{APIVersion: "1", APIKey: "foo", Topic: "topic1"}
	rule2 := kafka.PortRule{APIVersion: "1", APIKey: "bar", Topic: "topic1"}
	rule3 := kafka.PortRule{APIVersion: "1", APIKey: "foo", Topic: "topic2"}

	rules := L7Rules{
		Kafka: []kafka.PortRule{rule1, rule2},
	}

	require.True(t, rule1.Exists(rules.Kafka))
	require.True(t, rule2.Exists(rules.Kafka))
	require.False(t, rule3.Exists(rules.Kafka))
}

func TestL7Equal(t *testing.T) {
	setUpSuite(t)

	rule1 := PortRuleL7{"Path": "/foo$", "Method": "GET"}
	rule2 := PortRuleL7{"Path": "/bar$", "Method": "GET"}
	rule3 := PortRuleL7{"Path": "/foo$", "Method": "GET", "extra": ""}

	require.True(t, rule1.Equal(rule1))
	require.True(t, rule2.Equal(rule2))
	require.True(t, rule3.Equal(rule3))
	require.False(t, rule1.Equal(rule2))
	require.False(t, rule2.Equal(rule1))
	require.False(t, rule1.Equal(rule3))
	require.False(t, rule3.Equal(rule1))
	require.False(t, rule2.Equal(rule3))
	require.False(t, rule3.Equal(rule2))

	rules := L7Rules{
		L7Proto: "testing",
		L7:      []PortRuleL7{rule1, rule2},
	}

	require.True(t, rule1.Exists(rules))
	require.True(t, rule2.Exists(rules))
	require.False(t, rule3.Exists(rules))
}

func TestValidateL4Proto(t *testing.T) {
	setUpSuite(t)

	require.NoError(t, L4Proto("TCP").Validate())
	require.NoError(t, L4Proto("UDP").Validate())
	require.NoError(t, L4Proto("ANY").Validate())
	require.Error(t, L4Proto("TCP2").Validate())
	require.Error(t, L4Proto("t").Validate())
}

func TestParseL4Proto(t *testing.T) {
	setUpSuite(t)

	p, err := ParseL4Proto("tcp")
	require.Equal(t, ProtoTCP, p)
	require.NoError(t, err)

	p, err = ParseL4Proto("Any")
	require.Equal(t, ProtoAny, p)
	require.NoError(t, err)

	p, err = ParseL4Proto("")
	require.Equal(t, ProtoAny, p)
	require.NoError(t, err)

	_, err = ParseL4Proto("foo2")
	require.Error(t, err)
}

func TestResourceQualifiedName(t *testing.T) {
	setUpSuite(t)

	// Empty resource name is passed through
	name, updated := ResourceQualifiedName("", "", "")
	require.Empty(t, name)
	require.False(t, updated)

	name, updated = ResourceQualifiedName("a", "", "")
	require.Empty(t, name)
	require.False(t, updated)

	name, updated = ResourceQualifiedName("", "b", "")
	require.Empty(t, name)
	require.False(t, updated)

	name, updated = ResourceQualifiedName("", "", "", ForceNamespace)
	require.Empty(t, name)
	require.False(t, updated)

	name, updated = ResourceQualifiedName("a", "", "", ForceNamespace)
	require.Empty(t, name)
	require.False(t, updated)

	name, updated = ResourceQualifiedName("", "b", "", ForceNamespace)
	require.Empty(t, name)
	require.False(t, updated)

	// Cluster-scope resources have no namespace
	name, updated = ResourceQualifiedName("", "", "test-resource")
	require.Equal(t, "//test-resource", name)
	require.True(t, updated)

	// Every resource has a name of a CEC they originate from
	name, updated = ResourceQualifiedName("", "test-name", "test-resource")
	require.Equal(t, "/test-name/test-resource", name)
	require.True(t, updated)

	// namespaced resources have a namespace
	name, updated = ResourceQualifiedName("test-namespace", "", "test-resource")
	require.Equal(t, "test-namespace//test-resource", name)
	require.True(t, updated)

	name, updated = ResourceQualifiedName("test-namespace", "test-name", "test-resource")
	require.Equal(t, "test-namespace/test-name/test-resource", name)
	require.True(t, updated)

	// resource names with slashes is considered to already be qualified, and will not be prepended with namespace/cec-name
	name, updated = ResourceQualifiedName("test-namespace", "test-name", "test/resource")
	require.Equal(t, "test/resource", name)
	require.False(t, updated)

	name, updated = ResourceQualifiedName("test-namespace", "test-name", "/resource")
	require.Equal(t, "/resource", name)
	require.False(t, updated)

	name, updated = ResourceQualifiedName("", "test-name", "test/resource")
	require.Equal(t, "test/resource", name)
	require.False(t, updated)

	name, updated = ResourceQualifiedName("", "test-name", "/resource")
	require.Equal(t, "/resource", name)
	require.False(t, updated)

	// forceNamespacing has no effect when the resource name is non-qualified
	name, updated = ResourceQualifiedName("", "", "test-resource", ForceNamespace)
	require.Equal(t, "//test-resource", name)
	require.True(t, updated)

	name, updated = ResourceQualifiedName("", "test-name", "test-resource", ForceNamespace)
	require.Equal(t, "/test-name/test-resource", name)
	require.True(t, updated)

	name, updated = ResourceQualifiedName("test-namespace", "", "test-resource", ForceNamespace)
	require.Equal(t, "test-namespace//test-resource", name)
	require.True(t, updated)

	name, updated = ResourceQualifiedName("test-namespace", "test-name", "test-resource", ForceNamespace)
	require.Equal(t, "test-namespace/test-name/test-resource", name)
	require.True(t, updated)

	// forceNamespacing qualifies names in foreign namespaces
	name, updated = ResourceQualifiedName("test-namespace", "test-name", "test/resource", ForceNamespace)
	require.Equal(t, "test-namespace/test-name/test/resource", name)
	require.True(t, updated)

	name, updated = ResourceQualifiedName("test-namespace", "test-name", "/resource", ForceNamespace)
	require.Equal(t, "test-namespace/test-name//resource", name)
	require.True(t, updated)

	name, updated = ResourceQualifiedName("", "test-name", "test/resource", ForceNamespace)
	require.Equal(t, "/test-name/test/resource", name)
	require.True(t, updated)

	// forceNamespacing skips prepending if namespace matches
	name, updated = ResourceQualifiedName("test-namespace", "test-name", "test-namespace/resource", ForceNamespace)
	require.Equal(t, "test-namespace/resource", name)
	require.False(t, updated)
	name, updated = ResourceQualifiedName("", "test-name", "/resource", ForceNamespace)
	require.Equal(t, "/resource", name)
	require.False(t, updated)
}

func TestParseQualifiedName(t *testing.T) {
	setUpSuite(t)

	// Empty name is passed through
	namespace, name, resourceName := ParseQualifiedName("")
	require.Empty(t, namespace)
	require.Empty(t, name)
	require.Empty(t, resourceName)

	// Unqualified name is passed through
	namespace, name, resourceName = ParseQualifiedName("resource")
	require.Empty(t, namespace)
	require.Empty(t, name)
	require.Equal(t, "resource", resourceName)

	// Cluster-scope resources have no namespace
	namespace, name, resourceName = ParseQualifiedName("//test-resource")
	require.Empty(t, namespace)
	require.Empty(t, name)
	require.Equal(t, "test-resource", resourceName)

	// Every resource has a name of a CEC they originate from
	namespace, name, resourceName = ParseQualifiedName("/test-name/test-resource")
	require.Empty(t, namespace)
	require.Equal(t, "test-name", name)
	require.Equal(t, "test-resource", resourceName)

	// namespaced resources have a namespace
	namespace, name, resourceName = ParseQualifiedName("test-namespace//test-resource")
	require.Equal(t, "test-namespace", namespace)
	require.Empty(t, name)
	require.Equal(t, "test-resource", resourceName)

	namespace, name, resourceName = ParseQualifiedName("test-namespace/test-name/test-resource")
	require.Equal(t, "test-namespace", namespace)
	require.Equal(t, "test-name", name)
	require.Equal(t, "test-resource", resourceName)

	// resource names with slashes is considered to already be qualified, and will not be prepended with namespace/cec-name
	namespace, name, resourceName = ParseQualifiedName("test/resource")
	require.Empty(t, namespace)
	require.Empty(t, name)
	require.Equal(t, "test/resource", resourceName)

	namespace, name, resourceName = ParseQualifiedName("/resource")
	require.Empty(t, namespace)
	require.Empty(t, name)
	require.Equal(t, "/resource", resourceName)

	// extra slashes are part of the resource name
	namespace, name, resourceName = ParseQualifiedName("test-namespace/test-name//resource")
	require.Equal(t, "test-namespace", namespace)
	require.Equal(t, "test-name", name)
	require.Equal(t, "/resource", resourceName)

	namespace, name, resourceName = ParseQualifiedName("/test-name/test/resource")
	require.Empty(t, namespace)
	require.Equal(t, "test-name", name)
	require.Equal(t, "test/resource", resourceName)
}
