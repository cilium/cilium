# Cilium node monitor

The node monitor provides an API for reading the events from the BPF datapath.
When the process `cilium-node-monitor` is started it handles new connections to
`$RuntimePath/monitor.sock`. Users of the API are expected to read the
[Meta][0] and [Payload][1] structs (encoded in gob). Since the payload can vary
in size to make decoding easier the Meta contains the size of the payload.  The
API is **not stable** yet and might change in the future. If you start depending
on the current behavior, please consider creating tests so that potential
breakage is detected earlier.

Notifications from the BPF datapath are transmitted via the perf ring buffer.
The perf ring buffer is a single reader data structure. The node monitor
provides access to the notifications to multiple readers by multiplexing all
notifications to all registered readers.

The node monitor is normally built together with the Cilium agent.  In the top
level Makefile there is a target which makes it easier to test both changes to
the agent and monitor by running

        $ make reload

If you prefer you can also compile the monitor separately

        $  make -C monitor

And then run it by

        $ ./monitor/cilium-node-monitor

Normally you would not need to run the monitor manually since it's already part
of the startup in the agent. In the unlikely case, you would need to run a
patched version of the monitor manually commenting out the call to
`go d.nodeMonitor.Run()` in the `runDaemon()` function is enough to stop the
agent from starting the node monitor and then you  can execute your version of
the node monitor.

[0]: https://godoc.org/github.com/cilium/cilium/pkg/monitor/payload#Meta
[1]: https://godoc.org/github.com/cilium/cilium/pkg/monitor/payload#Payload
