Introducing New CRDs
====================

Cilium uses a combination of code generation tools to facilitate adding
CRDs to the Kubernetes instance it is installed on.

These CRDs make themselves available in the generated Kubernetes client
Cilium uses.

Defining And Generating CRDs
----------------------------

Currently, two API versions exist ``v2`` and ``v2alpha1``.

Paths:

::

   pkg/k8s/apis/cilium.io/v2/
   pkg/k8s/apis/cilium.io/v2alpha1/

CRDs are defined via Golang structures, annotated with ``marks``, and
generated with Cilium make file targets.

Marks
~~~~~

Marks are used to tell ``controller-gen`` *how* to generate the CRD.
This includes defining the CRD's various names (Singular, plural,
group), its Scope (Cluster, Namespaced), Shortnames, etc…

An example:

::

   // +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

   // +kubebuilder:resource:categories={cilium},singular="ciliumendpointslice",path="ciliumendpointslices",scope="Cluster",shortName={ces}

   // +kubebuilder:storageversion

You can find CRD generation ``marks`` documentation
`here <https://book.kubebuilder.io/reference/markers/crd.html>`__.

Marks are also used to generate json-schema validation. You can define
validation criteria such as "format=cidr" and "required" via validation
``marks`` in your struct's comments.

An example:

.. code-block:: go

   type CiliumBGPPeeringConfiguration struct {
       // PeerAddress is the IP address of the peer.
       // This must be in CIDR notation and use a /32 to express
       // a single host.
       //
       // +kubebuilder:validation:Required
       // +kubebuilder:validation:Format=cidr
       PeerAddress string `json:"peerAddress"`

You can find CRD validation ``marks`` documentation
`here <https://book.kubebuilder.io/reference/markers/crd-validation.html>`__.

Defining CRDs
~~~~~~~~~~~~~

Paths:

::

   pkg/k8s/apis/cilium.io/v2/
   pkg/k8s/apis/cilium.io/v2alpha1/

The portion of the directory after ``apis/`` makes up the CRD's
``Group`` and ``Version``. See
`KubeBuilder-GVK <https://book.kubebuilder.io/cronjob-tutorial/gvks.html>`__

You can begin defining your ``CRD`` structure, making any subtypes you
like to adequately define your data model and using ``marks`` to control
the CRD generation process.

Here is a brief example, omitting any further definitions of sub-types
to express the CRD data model.

.. code-block:: go

   // +genclient
   // +genclient:nonNamespaced
   // +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
   // +kubebuilder:resource:categories={cilium,ciliumbgp},singular="ciliumbgppeeringpolicy",path="ciliumbgppeeringpolicies",scope="Cluster",shortName={bgpp}
   // +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",name="Age",type=date
   // +kubebuilder:storageversion

   // CiliumBGPPeeringPolicy is a Kubernetes third-party resource for instructing
   // Cilium's BGP control plane to create peers.
   type CiliumBGPPeeringPolicy struct {
       // +k8s:openapi-gen=false
       // +deepequal-gen=false
       metav1.TypeMeta `json:",inline"`
       // +k8s:openapi-gen=false
       // +deepequal-gen=false
       metav1.ObjectMeta `json:"metadata"`

       // Spec is a human readable description of a BGP peering policy
       //
       // +kubebuilder:validation:Required
       Spec CiliumBGPPeeringPolicySpec `json:"spec,omitempty"`
   }

Integrating CRDs Into Cilium
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once you've coded your CRD data model you can use Cilium's ``make``
infrastructure to generate and integrate your CRD into Cilium.

There are several make targets and a script which revolve around
generating CRD and associated code gen (client, informers, ``DeepCopy``
implementations, ``DeepEqual`` implementations, etc).

Each of the next sections also detail the steps you should take to
integrate your CRD into Cilium.

Generating CRD YAML
~~~~~~~~~~~~~~~~~~~

To simply generate the CRDs and copy them into the correct location you
must perform two tasks:

* Update the ``Makefile`` to edit the ``CRDS_CILIUM_V2`` or
  ``CRDS_CILIUM_V2ALPHA1`` variable (depending on the version of your new CRD)
  to contain the plural name of your new CRD.
* Run ``make manifests``

This will generate your Golang structs into CRD manifests and copy them
to ``./pkg/k8s/apis/cilium.io/client/crds/`` into the appropriate
``Version`` directory.

You can inspect your generated ``CRDs`` to confirm they look OK.

Additionally ``./contrib/scripts/check-k8s-code-gen.sh`` is a script
which will generate the CRD manifest along with generating the necessary K8s 
API changes to use your CRDs via K8s client in Cilium source code.

Generating Client Code
~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: shell-session

    make generate-k8s-api

This make target will perform the necessary code-gen to integrate your
CRD into Cilium's ``client-go`` client, create listers, watchers, and
informers.

Again, multiple steps must be taken to fully integrate your CRD into
Cilium.

Register With API Scheme
~~~~~~~~~~~~~~~~~~~~~~~~

Paths:

::

    pkg/k8s/apis/cilium.io/v2alpha1/register.go

Make a change similar to this diff to register your CRDs with the API
scheme.

.. code-block:: diff

   diff --git a/pkg/k8s/apis/cilium.io/v2alpha1/register.go b/pkg/k8s/apis/cilium.io/v2alpha1/register.go
   index 9650e32f8d..0d85c5a233 100644
   --- a/pkg/k8s/apis/cilium.io/v2alpha1/register.go
   +++ b/pkg/k8s/apis/cilium.io/v2alpha1/register.go
   @@ -55,6 +55,34 @@ const (
    
           // CESName is the full name of Cilium Endpoint Slice
           CESName = CESPluralName + "." + CustomResourceDefinitionGroup
   +
   +       // Cilium BGP Peering Policy (BGPP)
   +
   +       // BGPPPluralName is the plural name of Cilium BGP Peering Policy
   +       BGPPPluralName = "ciliumbgppeeringpolicies"
   +
   +       // BGPPKindDefinition is the kind name of Cilium BGP Peering Policy
   +       BGPPKindDefinition = "CiliumBGPPeeringPolicy"
   +
   +       // BGPPName is the full name of Cilium BGP Peering Policy
   +       BGPPName = BGPPPluralName + "." + CustomResourceDefinitionGroup
   +
   +       // Cilium BGP Load Balancer IP Pool (BGPPool)
   +
   +       // BGPPoolPluralName is the plural name of Cilium BGP Load Balancer IP Pool
   +       BGPPoolPluralName = "ciliumbgploadbalancerippools"
   +
   +       // BGPPoolKindDefinition is the kind name of Cilium BGP Peering Policy
   +       BGPPoolKindDefinition = "CiliumBGPLoadBalancerIPPool"
   +
   +       // BGPPoolName is the full name of Cilium BGP Load Balancer IP Pool
   +       BGPPoolName = BGPPoolPluralName + "." + CustomResourceDefinitionGroup
    )
    
    // SchemeGroupVersion is group version used to register these objects
   @@ -102,6 +130,10 @@ func addKnownTypes(scheme *runtime.Scheme) error {
                   &CiliumEndpointSlice{},
                   &CiliumEndpointSliceList{},
   +               &CiliumBGPPeeringPolicy{},
   +               &CiliumBGPPeeringPolicyList{},
   +               &CiliumBGPLoadBalancerIPPool{},
   +               &CiliumBGPLoadBalancerIPPoolList{},
           )
    
           metav1.AddToGroupVersion(scheme, SchemeGroupVersion)

You should also bump the ``CustomResourceDefinitionSchemaVersion``
variable in ``register.go`` to instruct Cilium
that new CRDs have been added to the system.

Register With Client
~~~~~~~~~~~~~~~~~~~~

``pkg/k8s/apis/cilium.io/client/register.go``

Make a change similar to the following to register CRD types with the
client.

.. code-block:: diff

   diff --git a/pkg/k8s/apis/cilium.io/client/register.go b/pkg/k8s/apis/cilium.io/client/register.go
   index ede134d7d9..ec82169270 100644
   --- a/pkg/k8s/apis/cilium.io/client/register.go
   +++ b/pkg/k8s/apis/cilium.io/client/register.go
   @@ -60,6 +60,12 @@ const (
    
           // CESCRDName is the full name of the CES CRD.
           CESCRDName = k8sconstv2alpha1.CESKindDefinition + "/" + k8sconstv2alpha1.CustomResourceDefinitionVersion
   +
   +       // BGPPCRDName is the full name of the BGPP CRD.
   +       BGPPCRDName = k8sconstv2alpha1.BGPPKindDefinition + "/" + k8sconstv2alpha1.CustomResourceDefinitionVersion
   +
   +       // BGPPoolCRDName is the full name of the BGPPool CRD.
   +       BGPPoolCRDName = k8sconstv2alpha1.BGPPoolKindDefinition + "/" + k8sconstv2alpha1.CustomResourceDefinitionVersion
    )
    
    var (
   @@ -86,6 +92,7 @@ func CreateCustomResourceDefinitions(clientset apiextensionsclient.Interface) er
                   synced.CRDResourceName(k8sconstv2.CLRPName):       createCRD(CLRPCRDName, k8sconstv2.CLRPName),
                   synced.CRDResourceName(k8sconstv2.CEGPName):       createCRD(CEGPCRDName, k8sconstv2.CEGPName),
                   synced.CRDResourceName(k8sconstv2alpha1.CESName):  createCRD(CESCRDName, k8sconstv2alpha1.CESName),
   +               synced.CRDResourceName(k8sconstv2alpha1.BGPPName): createCRD(BGPPCRDName, k8sconstv2alpha1.BGPPName),
           }
           for _, r := range synced.AllCiliumCRDResourceNames() {
                   fn, ok := resourceToCreateFnMapping[r]
   @@ -127,6 +134,12 @@ var (
    
           //go:embed crds/v2alpha1/ciliumendpointslices.yaml
           crdsv2Alpha1Ciliumendpointslices []byte
   +
   +       //go:embed crds/v2alpha1/ciliumbgppeeringpolicies.yaml
   +       crdsv2Alpha1Ciliumbgppeeringpolicies []byte
   +
   +       //go:embed crds/v2alpha1/ciliumbgploadbalancerippools.yaml
   +       crdsv2Alpha1Ciliumbgploadbalancerippools []byte
    )
    
    // GetPregeneratedCRD returns the pregenerated CRD based on the requested CRD


``pkg/k8s/watchers/watcher.go``

Also, configure the watcher for this resource (or tell the agent not to watch it)

.. code-block:: diff

   diff --git a/pkg/k8s/watchers/watcher.go b/pkg/k8s/watchers/watcher.go
   index eedf397b6b..8419eb90fd 100644
   --- a/pkg/k8s/watchers/watcher.go
   +++ b/pkg/k8s/watchers/watcher.go
   @@ -398,6 +398,7 @@ var ciliumResourceToGroupMapping = map[string]watcherInfo{
         synced.CRDResourceName(v2.CECName):           {afterNodeInit, k8sAPIGroupCiliumEnvoyConfigV2},
         synced.CRDResourceName(v2alpha1.BGPPName):    {skip, ""}, // Handled in BGP control plane
         synced.CRDResourceName(v2alpha1.BGPPoolName): {skip, ""}, // Handled in BGP control plane
   +     synced.CRDResourceName(v2.CCOName):           {skip, ""}, // Handled by init directly


Getting Your CRDs Installed
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Your new CRDs must be installed into Kubernetes. This is controlled in
the ``pkg/k8s/synced/crd.go`` file.

Here is an example diff which installs the CRDs ``v2alpha1.BGPPName``
and ``v2alpha.BGPPoolName``:

.. code-block:: diff

   diff --git a/pkg/k8s/synced/crd.go b/pkg/k8s/synced/crd.go
   index 52d975c449..10c554cf8a 100644
   --- a/pkg/k8s/synced/crd.go
   +++ b/pkg/k8s/synced/crd.go
   @@ -42,6 +42,11 @@ func agentCRDResourceNames() []string {
                   CRDResourceName(v2.CCNPName),
                   CRDResourceName(v2.CNName),
                   CRDResourceName(v2.CIDName),
   +               CRDResourceName(v2.CIDName),
   +               // TODO(louis) make this a conditional install
   +               // based on --enable-bgp-control-plane flag
   +               CRDResourceName(v2alpha1.BGPPName),
   +               CRDResourceName(v2alpha1.BGPPoolName),
           }

Updating RBAC Roles
~~~~~~~~~~~~~~~~~~~

Cilium is installed with a service account and this service account
should be given RBAC permissions to access your new CRDs. The following
files should be updated to include permissions to create, read, update, and delete 
your new CRD.

::

   install/kubernetes/cilium/templates/cilium-agent/clusterrole.yaml
   install/kubernetes/cilium/templates/cilium-operator/clusterrole.yaml
   install/kubernetes/cilium/templates/cilium-preflight/clusterrole.yaml

Here is a diff of updating the Agent's cluster role template to include
our new BGP CRDs:

.. code-block:: diff

   diff --git a/install/kubernetes/cilium/templates/cilium-agent/clusterrole.yaml b/install/kubernetes/cilium/templates/cilium-agent/clusterrole.yaml
   index 9878401a81..5ba6c30cd7 100644
   --- a/install/kubernetes/cilium/templates/cilium-agent/clusterrole.yaml
   +++ b/install/kubernetes/cilium/templates/cilium-agent/clusterrole.yaml
   @@ -102,6 +102,8 @@ rules:
      - ciliumlocalredirectpolicies/finalizers
      - ciliumendpointslices
   +  - ciliumbgppeeringpolicies
   +  - ciliumbgploadbalancerippools
      verbs:
      - '*'
    {{- end }}

It's important to note, neither the Agent nor the Operator installs
these manifests to the Kubernetes clusters. This means when testing your
CRD out the updated ``clusterrole`` must be written to the cluster
manually.

Also please note, you should be specific about which 'verbs' are added to the
Agent's cluster role. 
This ensures a good security posture and best practice.

A convenient script for this follows:

.. code-block:: bash

   createTemplate(){
       if [ -z "${1}" ]; then
           echo "Commit SHA not set"
           return
       fi
       ciliumVersion=${1}
   MODIFY THIS LINE CD TO CILIUM ROOT DIR <-----
   cd install/kubernetes
   CILIUM_CI_TAG="${1}"
   helm template cilium ./cilium \
     --namespace kube-system \
     --set image.repository=quay.io/cilium/cilium-ci \
     --set image.tag=$CILIUM_CI_TAG \
     --set operator.image.repository=quay.io/cilium/operator \
     --set operator.image.suffix=-ci \
     --set operator.image.tag=$CILIUM_CI_TAG \
     --set clustermesh.apiserver.image.repository=quay.io/cilium/clustermesh-apiserver-ci \
     --set clustermesh.apiserver.image.tag=$CILIUM_CI_TAG \
     --set hubble.relay.image.repository=quay.io/cilium/hubble-relay-ci \
     --set hubble.relay.image.tag=$CILIUM_CI_TAG > /tmp/cilium.yaml
   echo "run kubectl apply -f /tmp/cilium.yaml"
   }

The above script with install Cilium and newest ``clusterrole``
manifests to anywhere your ``kubectl`` is pointed.
