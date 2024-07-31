// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"testing"

	"github.com/cilium/proxy/pkg/policy/api/kafka"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/fqdn/re"
)

func setUpSuite(_ testing.TB) {
	re.InitRegexCompileLRU(defaults.FQDNRegexCompileLRUSize)
}

func TestHTTPEqual(t *testing.T) {
	setUpSuite(t)

	rule1 := PortRuleHTTP{Path: "/foo$", Method: "GET", Headers: []string{"X-Test: Foo"}}
	rule2 := PortRuleHTTP{Path: "/bar$", Method: "GET", Headers: []string{"X-Test: Foo"}}
	rule3 := PortRuleHTTP{Path: "/foo$", Method: "GET", Headers: []string{"X-Test: Bar"}}

	require.Equal(t, true, rule1.Equal(rule1))
	require.Equal(t, false, rule1.Equal(rule2))
	require.Equal(t, false, rule1.Equal(rule3))

	rules := L7Rules{
		HTTP: []PortRuleHTTP{rule1, rule2},
	}

	require.Equal(t, true, rule1.Exists(rules))
	require.Equal(t, true, rule2.Exists(rules))
	require.Equal(t, false, rule3.Exists(rules))
}

func TestKafkaEqual(t *testing.T) {
	setUpSuite(t)

	rule1 := kafka.PortRule{APIVersion: "1", APIKey: "foo", Topic: "topic1"}
	rule2 := kafka.PortRule{APIVersion: "1", APIKey: "bar", Topic: "topic1"}
	rule3 := kafka.PortRule{APIVersion: "1", APIKey: "foo", Topic: "topic2"}

	require.Equal(t, rule1, rule1)
	require.NotEqual(t, rule2, rule1)
	require.NotEqual(t, rule3, rule1)

	rules := L7Rules{
		Kafka: []kafka.PortRule{rule1, rule2},
	}

	require.Equal(t, true, rule1.Exists(rules.Kafka))
	require.Equal(t, true, rule2.Exists(rules.Kafka))
	require.Equal(t, false, rule3.Exists(rules.Kafka))
}

func TestL7Equal(t *testing.T) {
	setUpSuite(t)

	rule1 := PortRuleL7{"Path": "/foo$", "Method": "GET"}
	rule2 := PortRuleL7{"Path": "/bar$", "Method": "GET"}
	rule3 := PortRuleL7{"Path": "/foo$", "Method": "GET", "extra": ""}

	require.Equal(t, true, rule1.Equal(rule1))
	require.Equal(t, true, rule2.Equal(rule2))
	require.Equal(t, true, rule3.Equal(rule3))
	require.Equal(t, false, rule1.Equal(rule2))
	require.Equal(t, false, rule2.Equal(rule1))
	require.Equal(t, false, rule1.Equal(rule3))
	require.Equal(t, false, rule3.Equal(rule1))
	require.Equal(t, false, rule2.Equal(rule3))
	require.Equal(t, false, rule3.Equal(rule2))

	rules := L7Rules{
		L7Proto: "testing",
		L7:      []PortRuleL7{rule1, rule2},
	}

	require.Equal(t, true, rule1.Exists(rules))
	require.Equal(t, true, rule2.Exists(rules))
	require.Equal(t, false, rule3.Exists(rules))
}

func TestValidateL4Proto(t *testing.T) {
	setUpSuite(t)

	require.Nil(t, L4Proto("TCP").Validate())
	require.Nil(t, L4Proto("UDP").Validate())
	require.Nil(t, L4Proto("ANY").Validate())
	require.NotNil(t, L4Proto("TCP2").Validate())
	require.NotNil(t, L4Proto("t").Validate())
}

func TestParseL4Proto(t *testing.T) {
	setUpSuite(t)

	p, err := ParseL4Proto("tcp")
	require.Equal(t, ProtoTCP, p)
	require.Nil(t, err)

	p, err = ParseL4Proto("Any")
	require.Equal(t, ProtoAny, p)
	require.Nil(t, err)

	p, err = ParseL4Proto("")
	require.Equal(t, ProtoAny, p)
	require.Nil(t, err)

	_, err = ParseL4Proto("foo2")
	require.NotNil(t, err)
}

func TestResourceQualifiedName(t *testing.T) {
	setUpSuite(t)

	// Empty resource name is passed through
	name, updated := ResourceQualifiedName("", "", "")
	require.Equal(t, "", name)
	require.Equal(t, false, updated)

	name, updated = ResourceQualifiedName("a", "", "")
	require.Equal(t, "", name)
	require.Equal(t, false, updated)

	name, updated = ResourceQualifiedName("", "b", "")
	require.Equal(t, "", name)
	require.Equal(t, false, updated)

	name, updated = ResourceQualifiedName("", "", "", ForceNamespace)
	require.Equal(t, "", name)
	require.Equal(t, false, updated)

	name, updated = ResourceQualifiedName("a", "", "", ForceNamespace)
	require.Equal(t, "", name)
	require.Equal(t, false, updated)

	name, updated = ResourceQualifiedName("", "b", "", ForceNamespace)
	require.Equal(t, "", name)
	require.Equal(t, false, updated)

	// Cluster-scope resources have no namespace
	name, updated = ResourceQualifiedName("", "", "test-resource")
	require.Equal(t, "//test-resource", name)
	require.Equal(t, true, updated)

	// Every resource has a name of a CEC they originate from
	name, updated = ResourceQualifiedName("", "test-name", "test-resource")
	require.Equal(t, "/test-name/test-resource", name)
	require.Equal(t, true, updated)

	// namespaced resources have a namespace
	name, updated = ResourceQualifiedName("test-namespace", "", "test-resource")
	require.Equal(t, "test-namespace//test-resource", name)
	require.Equal(t, true, updated)

	name, updated = ResourceQualifiedName("test-namespace", "test-name", "test-resource")
	require.Equal(t, "test-namespace/test-name/test-resource", name)
	require.Equal(t, true, updated)

	// resource names with slashes is considered to already be qualified, and will not be prepended with namespace/cec-name
	name, updated = ResourceQualifiedName("test-namespace", "test-name", "test/resource")
	require.Equal(t, "test/resource", name)
	require.Equal(t, false, updated)

	name, updated = ResourceQualifiedName("test-namespace", "test-name", "/resource")
	require.Equal(t, "/resource", name)
	require.Equal(t, false, updated)

	name, updated = ResourceQualifiedName("", "test-name", "test/resource")
	require.Equal(t, "test/resource", name)
	require.Equal(t, false, updated)

	name, updated = ResourceQualifiedName("", "test-name", "/resource")
	require.Equal(t, "/resource", name)
	require.Equal(t, false, updated)

	// forceNamespacing has no effect when the resource name is non-qualified
	name, updated = ResourceQualifiedName("", "", "test-resource", ForceNamespace)
	require.Equal(t, "//test-resource", name)
	require.Equal(t, true, updated)

	name, updated = ResourceQualifiedName("", "test-name", "test-resource", ForceNamespace)
	require.Equal(t, "/test-name/test-resource", name)
	require.Equal(t, true, updated)

	name, updated = ResourceQualifiedName("test-namespace", "", "test-resource", ForceNamespace)
	require.Equal(t, "test-namespace//test-resource", name)
	require.Equal(t, true, updated)

	name, updated = ResourceQualifiedName("test-namespace", "test-name", "test-resource", ForceNamespace)
	require.Equal(t, "test-namespace/test-name/test-resource", name)
	require.Equal(t, true, updated)

	// forceNamespacing qualifies names in foreign namespaces
	name, updated = ResourceQualifiedName("test-namespace", "test-name", "test/resource", ForceNamespace)
	require.Equal(t, "test-namespace/test-name/test/resource", name)
	require.Equal(t, true, updated)

	name, updated = ResourceQualifiedName("test-namespace", "test-name", "/resource", ForceNamespace)
	require.Equal(t, "test-namespace/test-name//resource", name)
	require.Equal(t, true, updated)

	name, updated = ResourceQualifiedName("", "test-name", "test/resource", ForceNamespace)
	require.Equal(t, "/test-name/test/resource", name)
	require.Equal(t, true, updated)

	// forceNamespacing skips prepending if namespace matches
	name, updated = ResourceQualifiedName("test-namespace", "test-name", "test-namespace/resource", ForceNamespace)
	require.Equal(t, "test-namespace/resource", name)
	require.Equal(t, false, updated)
	name, updated = ResourceQualifiedName("", "test-name", "/resource", ForceNamespace)
	require.Equal(t, "/resource", name)
	require.Equal(t, false, updated)
}

func TestParseQualifiedName(t *testing.T) {
	setUpSuite(t)

	// Empty name is passed through
	namespace, name, resourceName := ParseQualifiedName("")
	require.Equal(t, "", namespace)
	require.Equal(t, "", name)
	require.Equal(t, "", resourceName)

	// Unqualified name is passed through
	namespace, name, resourceName = ParseQualifiedName("resource")
	require.Equal(t, "", namespace)
	require.Equal(t, "", name)
	require.Equal(t, "resource", resourceName)

	// Cluster-scope resources have no namespace
	namespace, name, resourceName = ParseQualifiedName("//test-resource")
	require.Equal(t, "", namespace)
	require.Equal(t, "", name)
	require.Equal(t, "test-resource", resourceName)

	// Every resource has a name of a CEC they originate from
	namespace, name, resourceName = ParseQualifiedName("/test-name/test-resource")
	require.Equal(t, "", namespace)
	require.Equal(t, "test-name", name)
	require.Equal(t, "test-resource", resourceName)

	// namespaced resources have a namespace
	namespace, name, resourceName = ParseQualifiedName("test-namespace//test-resource")
	require.Equal(t, "test-namespace", namespace)
	require.Equal(t, "", name)
	require.Equal(t, "test-resource", resourceName)

	namespace, name, resourceName = ParseQualifiedName("test-namespace/test-name/test-resource")
	require.Equal(t, "test-namespace", namespace)
	require.Equal(t, "test-name", name)
	require.Equal(t, "test-resource", resourceName)

	// resource names with slashes is considered to already be qualified, and will not be prepended with namespace/cec-name
	namespace, name, resourceName = ParseQualifiedName("test/resource")
	require.Equal(t, "", namespace)
	require.Equal(t, "", name)
	require.Equal(t, "test/resource", resourceName)

	namespace, name, resourceName = ParseQualifiedName("/resource")
	require.Equal(t, "", namespace)
	require.Equal(t, "", name)
	require.Equal(t, "/resource", resourceName)

	// extra slashes are part of the resource name
	namespace, name, resourceName = ParseQualifiedName("test-namespace/test-name//resource")
	require.Equal(t, "test-namespace", namespace)
	require.Equal(t, "test-name", name)
	require.Equal(t, "/resource", resourceName)

	namespace, name, resourceName = ParseQualifiedName("/test-name/test/resource")
	require.Equal(t, "", namespace)
	require.Equal(t, "test-name", name)
	require.Equal(t, "test/resource", resourceName)
}
