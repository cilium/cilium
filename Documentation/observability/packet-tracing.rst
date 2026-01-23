.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _packet_tracing_tutorial:

***************************************************
Tutorial: Monitoring Generic IP Options with Cilium
***************************************************

This tutorial demonstrates how to configure Cilium to detect, extract, and
monitor arbitrary IP Options from network packets.

Cilium v1.19 and later implements `IP Options packet tracing <https://github.com/cilium/cilium/pull/41306>`_.
This feature supports reading specific IP Options (configured via Helm) and displaying
the extracted data within **Cilium Monitor** and **Hubble**. This capability is
essential for observing network metadata injected by sidecars or upstream
appliances.

Note that Cilium is responsible only for **observing** these Trace IDs. Users are
responsible for ensuring that their applications, sidecars, or network devices
are configured to **inject** the desired IP Options into the traffic.

In this guide, we use **Grafana Beyla** to inject eBPF-based Trace IDs (IP Option 136)
into traffic, and configure Cilium to extract and visualize this data.

.. note::
   The application architecture in this tutorial is based on the `Grafana Beyla Cilium Compatibility Demo <https://grafana.com/docs/beyla/latest/cilium-compatibility/#beyla-and-cilium-demo>`_.

Implementation Note: Data Truncation
====================================

.. warning::
   **Current Limitation:** The standard Trace ID injected by Beyla carries 18 bytes
   of payload data. The current Cilium BPF trace parser implementation supports
   storing a maximum of **8 bytes**.
   
   Cilium will capture the first 8 bytes of the Option 136 payload and truncate
   the remainder. This is sufficient for demonstrating the data flow, but full 
   Trace ID propagation requires future support for larger payload storage.

Prerequisites
=============

* **Kernel Version:** A Linux Kernel **>= 6.6** is recommended to support **TCX**, allowing Beyla and Cilium to coexist on the same interface without conflict.
* **Dependencies:** ``kind``, ``helm``, ``docker``, and the ``cilium`` CLI.

Step 1: Cluster Setup
=====================

We will create a Kind cluster and install Cilium with the ``bpf.monitorTraceIPOption``
flag enabled. This tells the BPF datapath to specifically look for Option 136.

1. **Create the Kind Cluster**
   Run the following from the root of your Cilium repository:

   .. code-block:: bash

      REPO_ROOT=$PWD
      KUBEPROXY_MODE="none" \
      WORKERS=2 \
      CONTROLPLANES=1 \
      CLUSTER_NAME=kind \
      IMAGE=kindest/node:v1.33.0 \
      make kind && \
      make kind-image && \
      kind export kubeconfig --name kind

2. **Install Cilium with IP Option Monitoring**
   Install Cilium using your local chart directory. The key flag here is ``--set bpf.monitorTraceIPOption=136``.
   This will configure Cilium to monitor IP Option 136 in the packet for trace context.

   .. code-block:: bash

      cilium install \
        --chart-directory ./install/kubernetes/cilium \
        --context $(kubectl config current-context) \
        --wait \
        --namespace kube-system \
        --set k8sServiceHost="kind-control-plane" \
        --set k8sServicePort="6443" \
        --set debug.enabled=true \
        --set debug.verbose=datapath \
        --set bpf.monitorTraceIPOption=136 \
        --set pprof.enabled=true \
        --set enableIPv4Masquerade=false \
        --set enableIPv6Masquerade=false \
        --set hostFirewall.enabled=false \
        --set socketLB.hostNamespaceOnly=true \
        --set kubeProxyReplacement=true \
        --set nodeinit.enabled=false \
        --set envoy.enabled=false \
        --set ipam.mode=kubernetes \
        --set ipv4.enabled=true \
        --set ipv4NativeRoutingCIDR=10.244.0.0/16 \
        --set ipv6.enabled=false \
        --set image.override="localhost:5000/cilium/cilium-dev:local" \
        --set image.pullPolicy=Never \
        --set operator.image.override="localhost:5000/cilium/operator-generic:local" \
        --set operator.image.pullPolicy=Never \
        --set operator.image.suffix="" \
        --set securityContext.privileged=true \
        --set gatewayAPI.enabled=false \
        --set socketLB.enabled=false \
        --set bpf.hostLegacyRouting=true \
        --set endpointRoutes.enabled=true \
        --set localRedirectPolicy=true \
        --set ciliumEndpointSlice.enabled=true \
        --set identityManagementMode=operator \
        --set prometheus.enabled=false \
        --set operator.prometheus.enabled=false \
        --set hubble.metrics.enableOpenMetrics=false \
        --set hubble.enabled=true \
        --set hubble.relay.enabled=true \
        --set hubble.listenAddress=":4244" \
        --set hubble.metrics.enabled="{dns,drop,tcp,flow,port-distribution,icmp,httpV2:exemplars=true;labelsContext=source_ip\,source_namespace\,source_workload\,destination_ip\,destination_namespace\,destination_workload\,traffic_direction}"

Step 2: Deploy Sample Applications
==================================

We deploy a chain of microservices (Node.js -> Go -> Python -> Rails) to generate
internal traffic that Beyla can instrument.

.. code-block:: text

    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: nodejs-deployment
      labels:
        app: node
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: node
      template:
        metadata:
          labels:
            app: node
        spec:
          containers:
            - name: node
              image: ghcr.io/grafana/beyla-test/nodejs-testserver
              ports:
                - containerPort: 3030
                  hostPort: 3030
    ---
    apiVersion: v1
    kind: Service
    metadata:
      name: node-service
    spec:
      type: NodePort
      selector:
        app: node
      ports:
        - name: node
          protocol: TCP
          port: 30030
          targetPort: 3030
          nodePort: 30030
    ---
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: go-deployment
      labels:
        app: go-testserver
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: go-testserver
      template:
        metadata:
          labels:
            app: go-testserver
        spec:
          containers:
            - name: go-testserver
              image: ghcr.io/grafana/beyla-test/go-testserver
              ports:
                - containerPort: 8080
                  hostPort: 8080
    ---
    apiVersion: v1
    kind: Service
    metadata:
      name: testserver
    spec:
      type: NodePort
      selector:
        app: go-testserver
      ports:
        - name: go-testserver
          protocol: TCP
          port: 8080
          targetPort: 8080
    ---
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: python-deployment
      labels:
        app: python-testserver
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: python-testserver
      template:
        metadata:
          labels:
            app: python-testserver
        spec:
          containers:
            - name: python-testserver
              image: ghcr.io/grafana/beyla-test/python-testserver
              ports:
                - containerPort: 8083
                  hostPort: 8083
    ---
    apiVersion: v1
    kind: Service
    metadata:
      name: pytestserver
    spec:
      type: NodePort
      selector:
        app: python-testserver
      ports:
        - name: python-testserver
          protocol: TCP
          port: 8083
          targetPort: 8083
    ---
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: rails-deployment
      labels:
        app: rails-testserver
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: rails-testserver
      template:
        metadata:
          labels:
            app: rails-testserver
        spec:
          containers:
            - name: rails-testserver
              image: ghcr.io/grafana/beyla-test/rails-testserver
              ports:
                - containerPort: 3040
                  hostPort: 3040
    ---
    apiVersion: v1
    kind: Service
    metadata:
      name: utestserver
    spec:
      type: NodePort
      selector:
        app: rails-testserver
      ports:
        - name: rails-testserver
          protocol: TCP
          port: 3040
          targetPort: 3040

Save the above to ``apps.yaml`` and apply:

.. code-block:: bash

    kubectl apply -f apps.yaml

Step 3: Deploy Grafana Beyla
============================

We deploy Beyla as a DaemonSet to automatically inject Trace IDs into the application traffic. Note the critical configuration for ``context_propagation`` and ``traffic_control_backend``.

Create Namespace and RBAC
-------------------------

.. code-block:: bash

    kubectl create namespace beyla --dry-run=client -o yaml | kubectl apply -f -

    cat <<EOF | kubectl apply -f -
    apiVersion: v1
    kind: ServiceAccount
    metadata:
      namespace: beyla
      name: beyla
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata:
      name: beyla
    rules:
      - apiGroups: [ "apps" ]
        resources: [ "replicasets", "deployments", "statefulsets", "daemonsets" ]
        verbs: [ "list", "watch" ]
      - apiGroups: [ "" ]
        resources: [ "pods", "services", "nodes", "replicationcontrollers", "namespaces" ]
        verbs: [ "list", "watch" ]
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRoleBinding
    metadata:
      name: beyla
    subjects:
      - kind: ServiceAccount
        name: beyla
        namespace: beyla
    roleRef:
      apiGroup: rbac.authorization.k8s.io
      kind: ClusterRole
      name: beyla
    EOF

Deploy ConfigMap and DaemonSet
------------------------------

To enable trace context propagation via IP headers, we set the ``context_propagation``
field to ``"ip"``. This instructs Beyla to inject the Trace ID directly into the packet
header (specifically IP Option 136), allowing network-layer tools like Cilium to observe
trace context without parsing L7 payloads.

For more details on configuration options, refer to the Grafana documentation on `Distributed Traces and Context Propagation <https://grafana.com/docs/beyla/latest/configure/metrics-traces-attributes/#distributed-traces-and-context-propagation>`_.

.. code-block:: text

    apiVersion: v1
    kind: ConfigMap
    metadata:
      namespace: beyla
      name: beyla-config
    data:
      beyla-config.yml: |
        attributes:
          kubernetes:
            enable: true
        routes:
          unmatched: heuristic
        discovery:
          instrument:
            - k8s_deployment_name: "nodejs-deployment"
            - k8s_deployment_name: "go-deployment"
            - k8s_deployment_name: "python-deployment"
            - k8s_deployment_name: "rails-deployment"
        trace_printer: text
        ebpf:
          # REQUIRED: Explicitly enable IP Option injection
          context_propagation: "ip"
          
          # REQUIRED: Use TCX to avoid BPF priority conflicts with Cilium
          traffic_control_backend: tcx
          
          disable_blackbox_cp: true
          track_request_headers: true
    ---
    apiVersion: apps/v1
    kind: DaemonSet
    metadata:
      namespace: beyla
      name: beyla
    spec:
      selector:
        matchLabels:
          instrumentation: beyla
      template:
        metadata:
          labels:
            instrumentation: beyla
        spec:
          serviceAccountName: beyla
          hostPID: true
          hostNetwork: true
          dnsPolicy: ClusterFirstWithHostNet
          containers:
            - name: beyla
              image: grafana/beyla:main
              securityContext:
                privileged: true
                readOnlyRootFilesystem: true
              volumeMounts:
                - mountPath: /config
                  name: beyla-config
                - mountPath: /var/run/beyla
                  name: var-run-beyla
              env:
                - name: BEYLA_CONFIG_PATH
                  value: "/config/beyla-config.yml"
          volumes:
            - name: beyla-config
              configMap:
                name: beyla-config
            - name: var-run-beyla
              emptyDir: {}

Save to ``beyla.yaml`` and apply:

.. code-block:: bash

    kubectl apply -f beyla.yaml

Step 4: Observing the Data
==========================

With the environment running, we can now observe the extracted IP Options via standard tools.

1. **Establish a Port Forward** to the application:

   .. code-block:: bash

       kubectl port-forward services/node-service 30030:30030 &

2. **Trigger Traffic:**

   .. code-block:: bash

       curl http://localhost:30030/traceme

3. **Identify the Workload Node:**
   Before running diagnostics, identify which Kind node is actually hosting the workload.

   .. code-block:: bash

       APP_NODE=$(kubectl get pod -l app=node -o jsonpath='{.items[0].spec.nodeName}')
       echo "Workload is running on: $APP_NODE"

4. **Verify on the Wire (tcpdump):**
   Install and run ``tcpdump`` on the specific node identified above.

   .. code-block:: bash

       # Install tcpdump on the correct node
       docker exec $APP_NODE bash -c "apt-get update && apt-get install -y tcpdump"

       # Sniff for IP Options (Header Length > 20 bytes)
       docker exec -it $APP_NODE tcpdump -i any -v -x "ip[0] & 0xf > 5"

   Look for ``options (unknown 136)`` in the output.

5. **Verify in Cilium Monitor:**
   Now, verify that the Cilium agent on that same node is extracting the data.

   .. code-block:: bash

       # Find the Cilium Agent pod running on the workload node
       CILIUM_AGENT=$(kubectl get pod -n kube-system -l k8s-app=cilium --field-selector spec.nodeName=$APP_NODE -o jsonpath='{.items[0].metadata.name}')

       # Exec into the agent and monitor for the Trace ID
       kubectl exec -it -n kube-system $CILIUM_AGENT -- cilium monitor -v | grep ip-trace-id

   You should observe output similar to the following, confirming that the ``ip-trace-id`` has been successfully extracted and associated with the flow:

   .. code-block:: text

      -> overlay flow 0x6a16c10e , identity 18548->13318 [ ip-trace-id = 12460542740415775846 ] state established ifindex cilium_vxlan orig-ip 0.0.0.0: 10.244.2.169:42532 -> 10.244.1.84:8080 tcp ACK

Using Hubble
============

You can also inspect these traces using the Hubble CLI. This allows you to view
the flow data in a structured format directly from your terminal.

1. **Build the CLI**:
   First, navigate to the Hubble directory and build the latest binary from source.
   This ensures you have the latest features, including the new IP option filters.

   .. code-block:: bash

       cd hubble
       make hubble

2. **Connect to the Cluster**:
   Establish a port forward to the Hubble Relay service. This opens a channel for the
   local CLI to communicate with the Hubble instance running inside your Kubernetes cluster.

   .. code-block:: bash

       cilium hubble port-forward &

3. **Observe and Filter**:
   Now, run the observer. We use the ``--ip-trace-option`` flag to filter specifically for 
   flows where Cilium has detected and extracted data from IP Option 136.

   .. code-block:: bash

       ./hubble observe -f --ip-trace-option 136

**Note on Filtering by ID:**
While Hubble also supports filtering by a specific ID value (e.g., ``--ip-trace-id 12345``),
this is not practical for the Grafana Beyla demo. Beyla generates random, unique Trace IDs
for every request, making it impossible to know the ID in advance. Therefore, filtering by
the **presence** of the option (using ``--ip-trace-option``) is the correct approach for
verifying that injection is working across the cluster.

**Important Configuration Requirement:**
The ``--ip-trace-option`` flag works only if the underlying Cilium agent is configured to
read that specific option. If a packet contains a Trace ID in Option 136, but Cilium was
installed with ``bpf.monitorTraceIPOption=123``, the agent will ignore the data, and Hubble
will show no results for your query. Always ensure your Hubble filter matches your Helm
configuration.