# Namespace-based Export Control Testing Infrastructure

This document describes the comprehensive testing infrastructure implemented for the namespace-based export control feature in Cilium ClusterMesh.

## Overview

The namespace-based export control feature allows fine-grained control over which namespaces export resources (CiliumEndpoints, CiliumIdentities, Services) to other clusters in a ClusterMesh setup. This testing infrastructure ensures the feature works reliably across all deployment scenarios.

## Test Components

### 1. Hive Script Tests

Located in `clustermesh-apiserver/clustermesh/testdata/`:

#### `namespace-filtering.txtar`
- Tests clustermesh-apiserver namespace filtering configuration
- Validates `CLUSTERMESH_DEFAULT_GLOBAL_NAMESPACE` environment variable support
- Verifies feature activation/deactivation behavior
- Tests backwards compatibility scenarios

#### `global-services-filtering.txtar`
- Tests global services integration with namespace filtering
- Validates that global services require both service annotation AND global namespace
- Tests service endpoint synchronization with namespace filtering

### 2. ClusterMesh Conformance Tests

Enhanced `.github/workflows/conformance-clustermesh.yaml`:

#### New Test Matrix Entry
```yaml
- name: '7'
  kernel: '54'
  kube-proxy: 'iptables'
  kpr: 'false'
  tunnel: 'vxlan'
  ipfamily: 'dual'
  encryption: 'false'
  endpoint-routes: 'false'
  ipv6-big-tcp: 'false'
  lb-mode: 'snat'
  lb-acceleration: 'false'
  node-port: 'false'
  kubeconfig-localhost: 'false'
  global-namespace-default: 'false'
  test-global-namespaces: 'true'
```

#### Configuration Features
- `clustermesh.defaultGlobalNamespace=false` - Security-first default
- Automatic `clustermesh.cilium.io/global=true` namespace annotations for connectivity tests
- Enhanced cilium-cli integration with `--namespace-annotations` flag

### 3. E2E Test Coverage

Extended `test/k8s/net_policies.go` with comprehensive test scenarios:

#### Test: "Tests global namespace annotations control resource export"
- Creates global and local namespaces
- Verifies resource export behavior
- Tests annotation changes and their effects

#### Test: "Tests complex network policy scenarios across global namespaces"
- L7 policy testing with HTTP path-based routing
- Cross-namespace communication validation
- Policy enforcement in global namespaces

#### Test: "Tests global namespace filtering edge cases and transitions"
- Filtering activation/deactivation scenarios
- Resource cleanup and backfill operations
- Edge case handling

#### Test: "Tests clustermesh-default-global-namespace configuration behavior"
- Environment variable configuration testing
- Default behavior validation
- Configuration change testing

#### Test: "Tests CiliumEndpoint and CiliumIdentity resources in global namespaces"
- Resource presence validation
- Endpoint detail verification
- Identity resource testing

#### Test: "Tests service discovery and load balancing across global namespaces"
- DNS resolution testing
- Load balancing validation
- Service scaling scenarios

### 4. Unit Tests

#### Core Package Tests
- `pkg/clustermesh/namespace_watcher_test.go` - Basic namespace watcher functionality
- `pkg/annotation/clustermesh_test.go` - Namespace-aware annotation functions
- `clustermesh-apiserver/clustermesh/*_test.go` - Integration tests

#### Mock Infrastructure
- Test doubles for namespace processors
- Fake Kubernetes client integration
- Resource indexing simulation

## Running the Tests

### Hive Script Tests
```bash
cd clustermesh-apiserver/clustermesh
go test -v . -run TestScript
```

### E2E Tests
```bash
cd test/k8s
go test -v . -run "Global Namespace"
```

### Unit Tests
```bash
# All clustermesh tests
go test -v ./pkg/clustermesh/...

# Annotation tests
go test -v ./pkg/annotation/...

# Clustermesh-apiserver tests
go test -v ./clustermesh-apiserver/clustermesh/...
```

### ClusterMesh Conformance
Runs automatically in CI with the new test matrix configuration.

## Test Scenarios Covered

### 1. Backwards Compatibility
- ✅ No annotations: All namespaces treated as global
- ✅ Exact same behavior as original ClusterMesh
- ✅ No performance impact when feature inactive

### 2. Feature Activation
- ✅ First namespace annotation triggers filtering
- ✅ Non-global namespace resources removed from etcd
- ✅ Only global namespace resources exported

### 3. Feature Deactivation
- ✅ Last annotation removal triggers deactivation
- ✅ All namespace resources backfilled to etcd
- ✅ Return to backwards compatible mode

### 4. Global Services Integration
- ✅ Service + namespace annotation requirements
- ✅ Endpoint slice synchronization
- ✅ Load balancing behavior

### 5. Configuration Management
- ✅ Environment variable support
- ✅ Default behavior configuration
- ✅ Helm chart integration

### 6. Edge Cases
- ✅ Rapid annotation changes
- ✅ Concurrent namespace operations
- ✅ Resource cleanup failures
- ✅ Network partition scenarios

## CI/CD Integration

The testing infrastructure integrates with existing Cilium CI/CD:

### Makefile Targets
- `make precheck` - Includes formatting and linting
- `make golangci-lint` - Code quality checks
- `make integration-tests` - Full test suite

### GitHub Actions
- Conformance test matrix automatically includes new test configuration
- Namespace annotation injection for clustermesh tests
- Automated test result validation

## Configuration Files

### Helm Values
```yaml
clustermesh:
  defaultGlobalNamespace: false  # Security-first default
```

### Environment Variables
```bash
CLUSTERMESH_DEFAULT_GLOBAL_NAMESPACE=false
```

### Namespace Annotations
```yaml
clustermesh.cilium.io/global: "true|false"
```

## Troubleshooting Tests

### Common Issues
1. **Test timeouts**: Increase timeout values in test configuration
2. **Resource conflicts**: Ensure proper test cleanup
3. **Network issues**: Validate cluster connectivity

### Debug Commands
```bash
# Check namespace filtering status
cilium clustermesh status --context $CLUSTER1

# Verify namespace annotations
kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.metadata.annotations.clustermesh\.cilium\.io/global}{"\n"}{end}'

# Check etcd contents
etcdctl get --prefix /cilium/state/
```

## Future Enhancements

### Planned Test Additions
- Performance impact measurement
- Multi-cluster upgrade scenarios
- Disaster recovery testing
- Load balancing fairness validation

### Test Infrastructure Improvements
- Automated test result analysis
- Performance regression detection
- Coverage gap identification
- Cross-platform validation

---

This testing infrastructure ensures that the namespace-based export control feature maintains reliability, security, and backwards compatibility across all supported Cilium deployment scenarios.