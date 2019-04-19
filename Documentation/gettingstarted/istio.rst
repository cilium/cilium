.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    http://docs.cilium.io

***************************
Getting Started Using Istio
***************************

This document serves as an introduction to using Cilium to enforce
security policies in Kubernetes micro-services managed with Istio.  It
is a detailed walk-through of getting a single-node Cilium + Istio
environment running on your machine.

.. include:: gsg_requirements.rst

.. note::

   If running on minikube, you may need to up the memory and CPUs
   available to the minikube VM from the defaults and/or the
   instructions provided here for the other GSGs. 6GB and 4 CPUs
   should be enough for Istio (``--memory=6144 --cpus=4``).

Step 2: Install Istio
=====================

.. note::

   Make sure that Cilium is running in your cluster before proceeding.

Install the `Helm client <https://docs.helm.sh/using_helm/#installing-helm>`_.

Download `Istio version 1.1.3
<https://github.com/istio/istio/releases/tag/1.1.2>`_:

::

   $ export ISTIO_VERSION=1.1.3
   $ curl -L https://git.io/getLatestIstio | sh -
   $ export ISTIO_HOME=`pwd`/istio-${ISTIO_VERSION}
   $ export PATH="$PATH:${ISTIO_HOME}/bin"

Create a copy of Istio's Helm charts in order to customize them:

::

    $ cp -r ${ISTIO_HOME}/install/kubernetes/helm/istio istio-cilium-helm

Configure the Cilium-specific variant of Pilot to inject the
Cilium network policy filters into each Istio sidecar proxy:

.. parsed-literal::

    $ curl -s \ |SCM_WEB|\/examples/kubernetes-istio/cilium-pilot.awk > cilium-pilot.awk

::

    $ awk -f cilium-pilot.awk \
          < ${ISTIO_HOME}/install/kubernetes/helm/istio/charts/pilot/templates/deployment.yaml \
          > istio-cilium-helm/charts/pilot/templates/deployment.yaml

Configure the Istio's sidecar injection to setup the transparent proxy mode
(TPROXY) as required by Cilium's proxy filters:

::

    $ sed -e 's,#interceptionMode: .*,interceptionMode: TPROXY,' \
          < ${ISTIO_HOME}/install/kubernetes/helm/istio/templates/configmap.yaml \
          > istio-cilium-helm/templates/configmap.yaml

Modify the Istio sidecar injection template to add an init container
that waits until DNS works and to mount Cilium's API Unix domain
sockets into each sidecar to allow Cilium's Envoy filters to query the
Cilium agent for policy configuration:

.. parsed-literal::

    $ curl -s \ |SCM_WEB|\/examples/kubernetes-istio/cilium-kube-inject.awk > cilium-kube-inject.awk

::

    $ awk -f cilium-kube-inject.awk \
          < ${ISTIO_HOME}/install/kubernetes/helm/istio/templates/sidecar-injector-configmap.yaml \
          > istio-cilium-helm/templates/sidecar-injector-configmap.yaml

Create an Istio deployment spec, which configures the Cilium-specific variant
of Pilot, and disables unused services:

::

    $ helm template istio-cilium-helm --name istio --namespace istio-system \
          --set pilot.image=docker.io/cilium/istio_pilot:${ISTIO_VERSION} \
          --set sidecarInjectorWebhook.enabled=false \
          --set global.controlPlaneSecurityEnabled=true \
          --set global.mtls.enabled=true \
          --set global.proxy.image=docker.io/cilium/istio_proxy:${ISTIO_VERSION} \
          --set ingress.enabled=false \
          --set egressgateway.enabled=false \
          > istio-cilium.yaml

.. TODO: Set global.controlPlaneSecurityEnabled=true and
   global.mtls.enabled=true when we stop seeing TLS connections getting
   forcefully closed by sidecar proxies sporadically.

Deploy Istio onto Kubernetes:

::

    $ kubectl create namespace istio-system
    $ helm template ${ISTIO_HOME}/install/kubernetes/helm/istio-init --name istio-init --namespace istio-system | kubectl apply -f -

Verify that 53 Istio CRDs have been created:

::

    $ watch "kubectl get crds | grep 'istio.io\|certmanager.k8s.io' | wc -l"

When the above returns '53', you can stop it with ``CTRL-c`` and deploy Istio:

::

    $ kubectl create -f istio-cilium.yaml

Check the progress of the deployment (every service should have an
``AVAILABLE`` count of ``1``):

::

    $ watch "kubectl get deployments -n istio-system"
    NAME                       DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
    istio-citadel              1         1         1            1           1m
    istio-galley               1         1         1            1           1m
    istio-ingressgateway       1         1         1            1           1m
    istio-pilot                1         1         1            1           1m
    istio-policy               1         1         1            1           1m
    istio-telemetry            1         1         1            1           1m
    prometheus                 1         1         1            1           1m

Once all Istio pods are ready, we are ready to install the demo
application.

Step 3: Deploy the Bookinfo Application
=======================================

Now that we have Cilium and Istio deployed, we can deploy version
``v1`` of the services of the `Istio Bookinfo sample application
<https://istio.io/docs/examples/bookinfo.html>`_.

From this point you can also follow the upstream `Istio Bookinfo
Applicatio example for Kubernetes
<https://istio.io/docs/examples/bookinfo/#if-you-are-running-on-kubernetes>`_.

Steps:

- Change the directory to `${ISTIO_VERSION}`, e.g.:

::

   $ cd istio-${ISTIO_VERSION}

- Deploy the application with manual sidecar injection:

::

   $ kubectl apply -f <(istioctl kube-inject -f samples/bookinfo/platform/kube/bookinfo.yaml)

- Verify that all pods are running:

::

   $ watch "kubectl get pods"

- Confirm that the Bookinfo application is running:

::

   $ kubectl exec -it $(kubectl get pod -l app=ratings -o jsonpath='{.items[0].metadata.name}') -c ratings -- curl productpage:9080/productpage | grep -o "<title>.*</title>"

- Define the ingress gateway for the application:

::

   $ kubectl apply -f samples/bookinfo/networking/bookinfo-gateway.yaml

- Set the ingress port:

::

   $ export INGRESS_PORT=$(kubectl -n istio-system get service istio-ingressgateway -o jsonpath='{.spec.ports[?(@.name=="http2")].nodePort}')

- Set the Ingress IP (for minikube, for other environments, see https://istio.io/docs/tasks/traffic-management/ingress/#determining-the-ingress-ip-and-ports):

::

   $ export INGRESS_HOST=$(minikube ip)

- Set the `GATEWAY_URL`:

::

   $ export GATEWAY_URL=$INGRESS_HOST:$INGRESS_PORT

- Confirn that the Bookinfo application is reachable from outside of the cluster:

::

   $ curl -s http://${GATEWAY_URL}/productpage | grep -o "<title>.*</title>"


Step 4: Clean Up
================

You have now installed Cilium and Istio, and deployed a demo app.  To clean up, run:

::

    $ minikube delete

After this, you can re-run the tutorial from Step 0.
