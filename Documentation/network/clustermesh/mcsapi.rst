.. _gs_clustermesh_mcsapi:

*********************************
Multi-Cluster Services API (Beta)
*********************************

.. include:: ../../beta.rst

This tutorial will guide you to through the support of `Multi-Cluster Services API (MCS-API)`_ in Cilium.

.. _Multi-Cluster Services API (MCS-API): https://github.com/kubernetes/enhancements/blob/master/keps/sig-multicluster/1645-multi-cluster-services-api/README.md

Prerequisites
#############

You need to have a functioning Cluster Mesh setup, please follow the
:ref:`gs_clustermesh` guide to set it up.

You first need to install the required MCS-API CRDs:

   .. code-block:: shell-session

      kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/mcs-api/62ede9a032dcfbc41b3418d7360678cb83092498/config/crd/multicluster.x-k8s.io_serviceexports.yaml
      kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/mcs-api/62ede9a032dcfbc41b3418d7360678cb83092498/config/crd/multicluster.x-k8s.io_serviceimports.yaml


To install Cilium with MCS-API support, run:

   .. parsed-literal::

      helm install cilium |CHART_RELEASE| \\
      --namespace kube-system \\
      --set clustermesh.enableMCSAPISupport=true

To enable MCS-API support on an existing Cilium installation, run:

   .. parsed-literal::

      helm upgrade cilium |CHART_RELEASE| \\
      --namespace kube-system \\
      --reuse-values \\
      --set clustermesh.enableMCSAPISupport=true

Also checkout the :ref:`EndpointSlice synchronization <endpointslicesync>` feature if you need Headless Services support.

Installing CoreDNS multicluster
-------------------------------

You also need to install and configure the `multicluster CoreDNS plugin`_.

.. _`multicluster CoreDNS plugin`: https://github.com/coredns/multicluster

The multicluster CoreDNS plugin is currently not provided by default in
CoreDNS so you will have to recompile it yourself.

To rebuild the CoreDNS image you need to first clone the `CoreDNS repo`_:

   .. code-block:: shell-session

      git clone https://github.com/coredns/coredns.git
      git checkout v1.11.4


Then you need add the multicluster plugin to the ``plugins.cfg`` file. The
ordering of plugins matters, add it just below kubernetes plugin that has very
similar functionality:

   .. parsed-literal::

      ...
      kubernetes:kubernetes
      multicluster:github.com/coredns/multicluster
      ...

.. _CoreDNS repo: https://github.com/coredns/coredns

Then you can build your image simply by running ``make`` and then ``docker build .``
with the right docker tag and upload it to your preferred registry.

You also need to make sure that CoreDNS is able to read and watch the relevant
MCS-API resources (ServiceImports). You can do so by running the following
command on each cluster:

   .. code-block:: shell-session

      kubectl patch clusterrole system:coredns --type=json \
         -p='[{"op":"add","path":"/rules/-","value":{"apiGroups":["multicluster.x-k8s.io"],"resources":["serviceimports"],"verbs":["list","watch"]}}]'

After that you will need to update the CoreDNS's Corefile to also enable the
multicluster plugin, for instance by executing the following command on each cluster:

   .. code-block:: shell-session

      kubectl get configmap -n kube-system coredns -o yaml | \
         sed -E -e 's/^(\s*)kubernetes.*cluster\.local.*$/\1multicluster clusterset.local\n&/' | \
         kubectl replace -f-

And you can finally deploy the CoreDNS image you previously built. Doing so will
also rollout the CoreDNS deployment and activate the Corefile change you previously made.

Exporting a Service
###################

To export a service you should create a ServiceExport resource. As a result
your Service will be exported to all clusters, provided that the Service
Namespace is present on those clusters.

   .. code-block:: yaml

      apiVersion: multicluster.x-k8s.io/v1alpha1
      kind: ServiceExport
      metadata:
         name: rebel-base

In all the clusters and for each set of exported Services that have the same name and namespace,
a ServiceImport resource will be automatically created. All the Endpoints from those exported Services
with the same name and namespace will be merged and made globally available.

An exported Service through MCS-API is available by default on the ``<svc>.<ns>.svc.clusterset.local`` domain.
If you have defined any hostname (via a Statefulset for instance) on your pods
each pods would also be available available through the ``<hostname>.<clustername>.<svc>.<ns>.svc.clusterset.local`` domain.

   .. note::

      The ``<clustername>.<svc>.<ns>.svc.clusterset.local`` domain that would allow
      to get all the endpoints of a Service in a specific cluster is not allowed!

      We recommend creating one service per cluster and/or region and exporting it
      accordingly if you do want to have this kind of behavior, for instance
      creating and exporting services ``mysvc-eu`` and ``mysvc-us`` instead of only
      one service. For more information checkout the `dedicated section in the MCS-API KEP`_
      explaining this behavior.

.. _dedicated section in the MCS-API KEP: https://github.com/kubernetes/enhancements/blob/master/keps/sig-multicluster/1645-multi-cluster-services-api/README.md#not-allowing-cluster-specific-targeting-via-dns

The ServiceImport has also a logic to merge different Service properties:

- SessionAffinity
- Ports (Union of the different ServiceExports)
- Type (ClusterSetIP/Headless)
- Annotations & Labels (via the ServiceExport ``exportedLabels`` and ``exportedAnnotations`` fields)

If any conflict arises on any of these properties, the oldest ServiceExport will
have precedence to resolve the conflict. This means that you should get a
consistent behavior globally for the same set of exported Services that has
the same name and namespace. If any conflicts arises, you would be able to see
details about it in the ServiceExport status Conditions.


Deploying a Simple Example Service using MCS-API
------------------------------------------------

1. In cluster 1, deploy:

   .. parsed-literal::

       kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/clustermesh/cluster1.yaml
       kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/clustermesh/mcsapi-example.yaml

2. In cluster 2, deploy:

   .. parsed-literal::

       kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/clustermesh/cluster2.yaml
       kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/clustermesh/mcsapi-example.yaml

3. From either cluster, access the exported service:

   .. parsed-literal::

      kubectl exec -ti deployment/x-wing -- curl rebel-base-mcsapi.default.svc.clusterset.local

   You will see replies from pods in both clusters.

Gateway-API
###########

Gateway-API has optional support for MCS-API via `GEP1748`_ by specifying a
ServiceImport backend, for example:

.. code-block:: yaml

   apiVersion: gateway.networking.k8s.io/v1
   kind: HTTPRoute
   metadata:
      name: rebel-base-mcsapi
      namespace: default
   spec:
      parentRefs:
      - group: gateway.networking.k8s.io
         kind: Gateway
         name: my-gateway
         namespace: default
      rules:
      - backendRefs:
         - group: multicluster.x-k8s.io
            kind: ServiceImport
            name: rebel-base-mcsapi
            port: 80
         matches:
         - method: GET
            path:
            type: PathPrefix
            value: /


The Gateway API implementation of Cilium fully support its own MCS-API implementation.

If you want to use another Gateway API implementation with the Cilium MCS-API implementation,
the Gateway API implementation you are using should officially support MCS-API / `GEP1748`_.

On the other hands, the Cilium Gateway API implementation only supports MCS-API
implementations using an underlying Service associated with a ServiceImport, and with
the annotation ``multicluster.kubernetes.io/derived-service`` on ServiceImport resources.

.. _GEP1748: https://github.com/kubernetes/enhancements/blob/master/keps/sig-multicluster/1645-multi-cluster-services-api/README.md
