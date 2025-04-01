# Cilium BGP Control Plane Testing Files

The `*.txtar` files located in this directory contain test scenarios for
testing BGP Control Plane component of the Cilium Agent.

The tests are driven by k8s resources, mainly `CiliumBGPNodeConfig` with node-specific
test BGP configuration and other `CiliumBGP*` resources (except for `CiliumBGPClusterConfig`,
which is processed only by the Cilium operator).
The expected state is validated against the test GoBGP instances that the Cilium BGP CP peers with.

The tests are using the [hive/script](https://docs.cilium.io/en/latest/contributing/development/hive/#testing-with-hive-script)
test framework, with additional BGP script commands for managing GoBGP test instances to peer with Cilium (`gobgp/*`)
and observing BGP state on Cilium (`bgp/*`).

## Managing GoBGP test instances
For creating and observing GoBGP instances that can be used to peer with Cilium, use the `gobgp/*` commands:

```
gobgp/add-peer [-s] [--server-asn=uint32] ip remote-asn
	Add a new peer the GoBGP server instance
gobgp/add-server [-r] [--router-id=string] asn ip port
	Add a new GoBGP server instance
gobgp/peers [-os] [--out=string] [--server-asn=uint32]
	List peers on the GoBGP server
gobgp/routes [-os] [--out=string] [--server-asn=uint32] [afi] [safi]
	List routes on the GoBGP server
gobgp/wait-state [-st] [--server-asn=uint32] [--timeout=duration] peer state
	Wait until the GoBGP peer is in the specified state
```

**Important**: Each test should use unique peering IPs, as the tests are executed in parallel.
These should be passed to the test infra via the `test-peering-ips` arg in the shebang at the beginning of the test,
for example:

```
#! --test-peering-ips=10.0.1.122,10.0.1.123
```

If duplicate peering IPs are detected during the test setup, the setup will fail with an error
message about duplicate IPs across the tests.

## Observing / asserting Cilium BGP Control Plane state
To observe / assert the state Cilium BGP Control Plane, use the `bgp/*` commands:

```
bgp/peers [-o] [--out=string]
	List BGP peers on Cilium
bgp/route-policies [-or] [--out=string] [--router-asn=uint32]
	List BGP route policies on Cilium
bgp/routes [-opr] [--out=string] [--peer=string] [--router-asn=uint32] [available|advertised] [afi] [safi]
	List BGP routes on Cilium
```

## Running tests
The tests need to be run as privileged, as they are adding/removing a testing network interface.
To execute all script tests from the `pkg/bgpv1/test` directory using sudo, run:

```
PRIVILEGED_TESTS=true go test -exec "sudo -E" . -test.run TestScript
```

You can run the tests with `-test.v` argument to show the verbose output with logs.

## Writing a test
When writing a test, you can run it with the `-scripttest.update` argument to automatically populate expected
data that is asserted with the `cmp` command.

## Debugging a test
In order to debug a test, put a `break` command anywhere in the test file. It will break into an interactive prompt
where you can use `bgp/*` / `gobgp/*` / other commands to observe the state.

You may want to enlarge the timeout of the test in the `testTimeout` constant in the `script_test.go` to get
more time for debugging.