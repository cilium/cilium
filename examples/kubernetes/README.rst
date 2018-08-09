Kubernetes Deployment
=====================

This directory contains all Cilium deployment files that can be used in
Kubernetes.

Each directory represents a Kubernetes version, from :code:`1.8` to :code:`1.12`,
and inside each version there is a list of files to deploy Cilium.

The structure directory will be :code:`${k8s_major_version}.${k8s_minor_version}/*.yaml`.

To generate those files simply run :code:`make`, which will pick up the Cilium
version from the :code:`VERSION` file at the root of the repository, or if you
want to specify the Cilium version yourself use
:code:`make CILIUM_VERSION=X.Y.Z`.

If you want to clean up a specific version, run :code:`make clean` which will
delete all generated files.

Templates
---------

There are templates for each component to be installed in Kubernetes inside
the directory :code:`templates`. The components ending with :code:`.sed` will be
automatically generated based on the template itself and the specific
:code:`transforms2sed.sed` inside each directory for each Kubernetes version.

Files
-----

Inside each :code:`${k8s_major_version}.${k8s_minor_version}` directory there
are 5 files:

- :code:`cilium-cm.yaml` - The :code:`ConfigMap` and options with some default
  values the user should change

- :code:`cilium-ds.yaml` - The :code:`DaemonSet` to deploy Cilium in the
  Kubernetes cluster, some advanced options can be changed here.

- :code:`cilium-sidecar-ds.yaml` - The :code:`DaemonSet` to deploy Cilium in
  the Kubernetes cluster in combination with Istio, some advanced options can
  be changed here.

- :code:`cilium-rbac.yaml` - The Cilium's RBAC for the Kubernetes cluster.

- :code:`cilium-sa.yaml` - The Cilium's Kubernetes :code:`ServiceAccount`.

- :code:`cilium.yaml` - All previous files concatenated into a single file,
  useful to deploy Cilium in a minikube environment with a "single line" command.

- :code:`cilium-sidecar.yaml` - All previous files concatenated into a single
  file, useful to deploy Cilium with Istio in a minikube environment with a
  "single line" command.

Add-ons
-------

You can find some add-ons to the Kubernetes + Cilium integration inside the
:code:`addons` directory.

Deprecated
----------

The usage of the files :code:`cilium.yaml` and :code:`rbac.yaml` should be
avoided as they can not provide a seamless integration with the kubernetes
cluster between upgrade. Please always use the files under
:code:`${k8s_major_version}.${k8s_minor_version}`.
