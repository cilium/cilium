.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

******************
Command Cheatsheet
******************

Cilium is controlled via an easy command-line interface. This CLI is a single
application that takes subcommands that you can find in the command reference
guide.

::

    $ cilium
    CLI for interacting with the local Cilium Agent

    Usage:
      cilium [command]

    Available Commands:
      bpf                      Direct access to local eBPF maps
      cleanup                  Reset the agent state
      completion               Output shell completion code for bash
      config                   Cilium configuration options
      debuginfo                Request available debugging information from agent
      endpoint                 Manage endpoints
      identity                 Manage security identities
      kvstore                  Direct access to the kvstore
      monitor                  Monitoring
      policy                   Manage security policies
      prefilter                Manage XDP CIDR filters
      service                  Manage services & loadbalancers
      status                   Display status of daemon
      version                  Print version information

    Flags:
          --config string   config file (default is $HOME/.cilium.yaml)
      -D, --debug           Enable debug messages
      -H, --host string     URI to server-side API

    Use "cilium [command] --help" for more information about a command.

All commands and subcommands have the option ``-h`` that will provide information
about the options and arguments that the subcommand has. In case of any error in
the command, Cilium CLI will return a non-zero status.

Command utilities:
==================

JSON Output
-----------

All the list commands will return a pretty printed list with the information
retrieved from Cilium Daemon. If you need something more detailed you can use JSON
output, to get the JSON output you can use the global option ``-o json``

::

    $ cilium endpoint list -o json

Moreover, Cilium also provides a `JSONPath
<https://goessner.net/articles/JsonPath/>`_ support, so detailed information can
be extracted. JSONPath template reference can be found in `Kubernetes
documentation <https://kubernetes.io/docs/reference/kubectl/jsonpath/>`_

::

    $ cilium endpoint list -o jsonpath='{[*].id}'
    29898 38939 56326
    $ cilium endpoint list -o jsonpath='{range [*]}{@.id}{"="}{@.status.policy.spec.policy-enabled}{"\n"}{end}'
    29898=none
    38939=none
    56326=none


Shell Tab-completion
--------------------

If you use bash or zsh, Cilium CLI can provide tab completion for subcommands.
If you want to install tab completion, you should run the following command in
your terminal.

::

   $ source <(cilium completion)

If you want to have Cilium completion always loaded, you can install using the
following:

::

    $ echo "source <(cilium completion)" >> ~/.bashrc


Command examples:
=================

Basics
------

Check the status of the agent
::

    $ cilium status
    KVStore:                Ok         Consul: 172.17.0.3:8300
    ContainerRuntime:       Ok
    Kubernetes:             Disabled
    Cilium:                 Ok         OK
    NodeMonitor:            Listening for events on 2 CPUs with 64x4096 of shared memory
    Cilium health daemon:   Ok
    Controller Status:      6/6 healthy
    Proxy Status:           OK, ip 10.15.28.238, port-range 10000-20000
    Cluster health:   1/1 reachable   (2018-04-11T07:33:09Z)
    $

Get a detailed status of the agent:
::

    $ cilium status --all-controllers --all-health --all-redirects
    KVStore:                Ok         Consul: 172.17.0.3:8300
    ContainerRuntime:       Ok
    Kubernetes:             Disabled
    Cilium:                 Ok         OK
    NodeMonitor:            Listening for events on 2 CPUs with 64x4096 of shared memory
    Cilium health daemon:   Ok
    Controller Status:      6/6 healthy
      Name                                 Last success   Last error   Count   Message
      kvstore-lease-keepalive              2m52s ago      never        0       no error
      ipcache-bpf-garbage-collection       2m50s ago      never        0       no error
      resolve-identity-29898               2m50s ago      never        0       no error
      sync-identity-to-k8s-pod (29898)     50s ago        never        0       no error
      sync-IPv4-identity-mapping (29898)   2m49s ago      never        0       no error
      sync-IPv6-identity-mapping (29898)   2m49s ago      never        0       no error
    Proxy Status:   OK, ip 10.15.28.238, port-range 10000-20000
    Cluster health:         1/1 reachable   (2018-04-11T07:32:09Z)
      Name                  IP              Reachable   Endpoints reachable
      runtime (localhost)   10.0.2.15       true        false
    $

Get the current agent configuration
::

    cilium config

Policy management
-----------------


Importing a Cilium Network Policy
::

    cilium policy import my-policy.json


Get list of all imported policy rules
::

	cilium policy get

Remove all policies
::

	cilium policy delete --all


Tracing
~~~~~~~


Check policy enforcement between two labels on port 80:
::

	cilium policy trace -s <app.from> -d <app.to> --dport 80


Check policy enforcement between two identities
::

    cilium policy trace --src-identity <from-id> --dst-identity <to-id>

Check policy enforcement between two pods:
::

    cilium policy trace --src-k8s-pod <namespace>:<pod.from> --dst-k8s-pod <namespace>:<pod.to>


Monitoring
~~~~~~~~~~~


Monitor cilium datapath notifications
::

    cilium monitor


Verbose output (including debug if enabled)
::

    cilium monitor -v

Extra verbose output (including packet dissection)
::

    cilium monitor -v -v


Filter for only the events related to endpoint
::

    cilium monitor --related-to=<id>


Filter for only events on layer 7
::

    cilium monitor -t L7


Show notifications only for dropped packet events
::

    cilium monitor --type drop


Don't dissect packet payload, display payload in hex information
::

    cilium monitor -v -v --hex



Connectivity
------------

Check cluster Connectivity
::

	cilium-health status

There is also a `blog post
<https://cilium.io/blog/2018/2/6/cilium-troubleshooting-cluster-health-monitor/>`_
related to this tool.

Endpoints
---------

Get list of all local endpoints
::

    cilium endpoint list

Get detailed view of endpoint properties and state
::

    cilium endpoint get <id>

Show recent endpoint specific log entries
::

    cilium endpoint log <id>

Enable debugging output on the cilium monitor for this endpoint
::

    cilium endpoint config <id> Debug=true


Loadbalancing
-------------

Get list of loadbalancer services
::

    cilium service list


Or you can get the loadbalancer information using bpf list
:::

    cilium bpf lb list


Add a new loadbalancer
::

    cilium service update --frontend 127.0.0.1:80 \
        --backends 127.0.0.2:90,127.0.0.3:90 \
        --id 20

eBPF
----

List node tunneling mapping information
::

    cilium bpf tunnel list

Checking logs for verifier issue
::

    journalctl -u cilium | grep -B20 -F10 Verifier

List connection tracking entries:
::

    sudo cilium bpf ct list global

Flush connection tracking entries:
::

    sudo cilium bpf ct flush

Kubernetes examples:
=====================

If you running Cilium on top of Kubernetes you may also want a way to list all
cilium endpoints or policies from a single Kubectl commands. Cilium provides all
this information to the user by using `Kubernetes Resource Definitions
<https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/>`_:

Policies
---------

In Kubernetes you can use two kinds of policies, Kubernetes Network Policies or
Cilium Network Policies. Both can be retrieved from the ``kubectl`` command:

.. code-block:: bash
   :name: Kubernetes Network Policies
   :caption: Kubernetes Network Policies

    kubectl get netpol

.. code-block:: bash
   :name: Kubernetes Cilium Policies
   :caption: Kubernetes Cilium Policies

    $ kubectl get cnp
    NAME      AGE
    rule1     3m
    $ kubectl get cnp rule1
    NAME      AGE
    rule1     3m
    $ kubectl get cnp rule1 -o json


Endpoints
----------

To retrieve a list of all endpoints managed by cilium, ``Cilium Endpoint``
resource can be used.

::

    $ kubectl get cep
    NAME                AGE
    34e299f0-b25c2fef   41s
    34e299f0-dd86986c   42s
    4d088f48-83e4f98d   2m
    4d088f48-d04ab55f   2m
    5c6211b5-9217a4d1   1m
    5c6211b5-dccc3d24   1m
    700e0976-6cb50b02   3m
    700e0976-afd3a30c   3m
    78092a35-4874ed16   1m
    78092a35-4b08b92b   1m
    9b74f61f-14571299   7s
    9b74f61f-f9a96f4a   7s

    $ kubectl get cep 700e0976-6cb50b02 -o json

    $ kubectl get cep -o jsonpath='{range .items[*]}{@.status.id}{"="}{@.status.status.policy.spec.policy-enabled}{"\n"}{end}'
    30391=ingress
    5766=ingress
    51796=none
    40355=none

