# Cilium Networking

Cilium networking is an experimental project to provide IPv6 networking with
native policy integration for containers based on eBPF programs running in
the Linux kernel.

## Requirements

Cilium is experimental and requires recent versions of the Linux kernel,
iproute2 and clang+LLVM. Specifically:
  * Linux kernel: https://git.breakpoint.cc/cgit/dborkman/net-next.git/log/?h=bpf-wip
  * iproute2: https://git.breakpoint.cc/cgit/dborkman/iproute2.git/log/?h=bpf-wip
  * clang+LLVM: 3.7.1

To ease installation and setup, we are providing a prebuilt Vagrant box with
all the requirements met. To use it, run:

  ```
  $ vagrant up
  ```

... in this directory which will bring up two vagrant boxes with Cilium
installed and running. If you have made any local changes you can at any time
run `vagrant reload` to synchronize your changes, rebuild and reinstall.

## Integration

Cilium provides integration plugins for:
  * libnetwork
  * CNI

## Development environment

1. Run the daemon

   ```
   $ sudo make run-cilium-daemon
   [...]
   ```

2. Run the plugin

   ```
   $ sudo make run-docker-plugin
   [...]
   ```

3. Run a container

   ```
   $ docker network create --driver cilium --ipam-driver cilium test-net
   $ docker run -ti --rm --net test-net ubuntu bash
   ```

## Detailed Instructions

### Setting up direct routing mode

This mode uses native IPv6 connectivty between the container hosts and does
not rely on encapsulation protocols.

1. Compile all components

  ```
  $ make
  ```

2. Run `cilium-net` in direct mode:

  ```
  $ cd cilium-net-daemon
  $ sudo ./run.sh -d eth0
  [...]
  $ cd docker-plugin
  $ sudo ./run.sh
  ```

  This will install a BPF program on eth0 which will pick packets destined for
  local containers.

3. Install routes to other container hosts

  In order to reach containers on other hosts. A route must exist, pointing the
  node subnet to the respective host. This can be achieved by running a routing
  daemon or by installing the routes manually:

  ```
  $ ip -6 route add beef::c0a8:79d9:0/128 dev eth0
  $ ip -6 route add beef::c0a8:79d9:0/112 via beef::c0a8:79d9:0
  ```
  In this example, `beef::c0a8:79d9:0` is the IPv6 node address of a container
  host. These routes must be configured on each other host.
