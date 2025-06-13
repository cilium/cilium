# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Essential Build Commands

### Building Components
- **Build all**: `make build`
- **Build with debug symbols**: `make debug` 
- **Build cilium-agent container**: `make build-container`
- **Build cilium-operator container**: `make build-container-operator`
- **Build BPF programs only**: `make -C bpf`

### Running Tests
- **Unit tests**: `go test ./...` or `make integration-tests`
- **Run specific package tests**: `go test ./pkg/kvstore` or `make integration-tests TESTPKGS=./pkg/kvstore`
- **Privileged tests** (requires root): `sudo make tests-privileged`
- **BPF unit tests**: `make run_bpf_tests`
- **Integration tests with kvstore**:
  ```bash
  make start-kvstores
  make integration-tests
  make stop-kvstores
  ```

### Code Quality Checks
- **Run all prechecks**: `make precheck`
- **Run linters**: `make lint` or `make golangci-lint`
- **Auto-fix lint issues**: `make lint-fix` or `make golangci-lint-fix`
- **Run postchecks**: `make postcheck` (updates command references and docs)
- **Check dev environment**: `make dev-doctor`

### Local Development with Kind
- **Create cluster**: `make kind`
- **Build and load images**: `make kind-image` (or `make kind-image-fast` on Linux)
- **Install Cilium**: `make kind-install-cilium` (or `make kind-install-cilium-fast`)
- **Tear down**: `make kind-down`

## High-Level Architecture

### Core Components
- **cilium-agent** (`daemon/`): Main dataplane agent running on each Kubernetes node
- **cilium-operator** (`operator/`): Cluster-wide operator managing CRDs and global state
- **cilium-health** (`cilium-health/`): Health checking between nodes
- **hubble-relay** (`hubble-relay/`): Observability data relay
- **clustermesh-apiserver** (`clustermesh-apiserver/`): Multi-cluster connectivity

### BPF Programs (`bpf/`)
The BPF programs implement the core datapath logic:
- `bpf_lxc.c`: Container/pod traffic handling
- `bpf_host.c`: Host namespace networking
- `bpf_overlay.c`: Overlay network (VXLAN/Geneve) handling
- `bpf_xdp.c`: XDP programs for early packet processing
- `lib/`: Shared BPF library code for common functionality

### Go Package Structure (`pkg/`)
Key packages that interact across multiple files:
- `datapath/`: BPF program management and compilation
- `endpoint/`: Endpoint (pod/container) lifecycle management
- `policy/`: Network policy engine and enforcement
- `identity/`: Security identity allocation and management
- `k8s/`: Kubernetes API watchers and state synchronization
- `bpf/`: BPF map management from userspace
- `loadbalancer/`: Service load balancing implementation
- `monitor/`: BPF event monitoring and decoding

### Cross-Component Interactions
1. **Policy Flow**: K8s watchers → Policy engine → Identity allocation → BPF map updates → Datapath enforcement
2. **Endpoint Creation**: CNI plugin → Daemon API → Endpoint manager → BPF compilation → Datapath activation
3. **Service Updates**: K8s service watcher → Load balancer → BPF service maps → Connection tracking

## Development Guidelines

### Testing Requirements
- All changes require unit tests
- Integration tests needed for cross-component features
- Privileged tests required for BPF/kernel interactions
- Use standard Go testing patterns

### Code Organization
- Go code follows standard Go conventions
- BPF code follows kernel coding style
- All commits must be signed-off: `git commit -s`
- API changes require OpenAPI spec updates in `api/`

### Dependencies
- Go >= 1.22 (check `go.mod` for current version)
- Clang/LLVM >= 18.1 for BPF compilation
- Linux kernel with BPF support
- Docker/Podman for container builds