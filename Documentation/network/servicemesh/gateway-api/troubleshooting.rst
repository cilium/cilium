This page guides you through the different mechanics of Gateway API and how to troubleshoot them.

Be sure to follow the Generic and Setup Verification steps from the :ref:`Troubleshooting Ingress & Service Mesh page<troubleshooting_servicemesh>`.

Checking resources
----------------------

#. Check the Gateway resource 

    .. code-block:: shell-session

      $ kubectl get gateway -A
      NAMESPACE                   NAME                 CLASS    ADDRESS          PROGRAMMED   AGE
      website                     http-gateway         cilium   172.21.255.202   True         5h
      webshop                     tls-gateway          cilium   172.21.255.203   True         5h
  
    The preceding command returns an overview of all the Gateways in the cluster. Check the following:

    * Is the Gateway programmed? 
    
        A programmed Gateway means that Cilium prepared a configuration for it.
      
      * If the ``Programmed true`` indicator is missing, make sure that Gateway API is enabled in the Cilium configuration.
  
    * Does the gateway have an address?
    
    You can check the service with ``kubectl get service``. 
    If the gateway has an address, it means that a LoadBalancer service is assigned to the gateway.
    If no IP appears, you might be missing a LoadBalancer implementation.
  
    * Is the class ``cilium``? 
    
    Cilium only programs Gateways with the class ``cilium``.
    
    * If the Gateway API resource type (``Gateway``, ``HTTPRoute``, etc.) is not found, make sure that the Gateway API CRDs are installed.

    You can use ``kubectl describe gateway`` to investigate issues more thoroughly.

    .. code-block:: shell-session

      $ kubectl describe gateway <name>

        Conditions:
          Message:               Gateway successfully scheduled
          Reason:                Accepted
          Status:                True
          Type:                  Accepted
          Message:               Gateway successfully reconciled
          Reason:                Programmed
          Status:                True
          Type:                  Programmed
          [...]
        Listeners:
          Attached Routes:  2
          Conditions:
            Message:               Listener Ready
            Reason:                Programmed
            Status:                True
            Type:                  Programmed
            Message:               Listener Accepted
            Reason:                Accepted
            Status:                True
            [...]

    You can see the general status of the gateway as well as the status of the configured listeners.
    
    Listener status displays the number of routes successfully attached to the listener.
    
    You can see status conditions for both gateway and listener:

      * ``Accepted``: the Gateway configuration was accepted.
      * ``Programmed``: the Gateway configuration was programmed into Envoy.
      * ``ResolvedRefs``: all referenced secrets were found and have permission for use.
  
    If any of these conditions are set to false, the ``Message`` and ``Reason`` fields give more information.

#. Check the HTTPRoute resource

  When the Gateway is functional, you can check the routes to verify if they are configured correctly.
  The way to check route status is similar to checking the status of a gateway resource. 
  
  While these instructions are written for HTTPRoute, they also apply to other route types.

  .. code-block:: shell-session

    $ kubectl get httproute -A
    NAMESPACE                 NAME              HOSTNAMES         AGE
    website                   homepage          www.example.org   17m
    webshop                   catalog-service                     17m
    webshop                   cart-service                        17m

  To get more information, enter ``kubectl describe httproute <name>``.

  .. code-block:: shell-session

    $ kubectl describe httproute <name>
    Status:
      Parents:
        Conditions:
          Last Transition Time:  2023-06-05T15:11:53Z
          Message:               Accepted HTTPRoute
          Observed Generation:   1
          Reason:                Accepted
          Status:                True
          Type:                  Accepted
          Last Transition Time:  2023-06-05T15:11:53Z
          Message:               Service reference is valid
          Observed Generation:   1
          Reason:                ResolvedRefs
          Status:                True
          Type:                  ResolvedRefs
        Controller Name:         io.cilium/gateway-controller
        Parent Ref:
          Group:  gateway.networking.k8s.io
          Kind:   Gateway
          Name:   same-namespace

  Status lists the conditions that are relevant for the specific ``HTTPRoute``.
  Conditions are listed by parent reference to the gateway. If you linked the route to multiple gateways, multiple entries appear.
  Conditions include ``Reason``, ``Type``, ``Status`` and ``Message``. ``Type`` indicates the condition type, and ``Status`` indicates with a boolean whether the condition type is met. Optionally, ``Message`` gives you more information about the condition.
  
  Notice the following condition types:

  * ``Accepted``: The HTTPRoute configuration was correct and accepted.
  * ``ResolvedRefs``: The referenced services were found and are valid references.
  
  If any of these are set to false, you can get more information by looking at the ``Message`` and ``Reason`` fields.

Common mistakes
---------------

.. include:: mistakes-warning.rst

* The backend service does not exist. 

    To verify whether the backend service was found, run ``kubectl describe httproute <name>`` and inspect the ``conditions`` field:
  
  .. code-block:: shell-session

        Parents:
          Conditions:
            Last Transition Time:  2023-06-06T13:55:10Z
            Message:               Service "backend" not found
            Observed Generation:   1
            Reason:                BackendNotFound
            Status:                False
            Type:                  ResolvedRefs
            Last Transition Time:  2023-06-06T13:55:10Z
            Message:               Accepted HTTPRoute
            Observed Generation:   1
            Reason:                Accepted
            Status:                True
            Type:                  Accepted
          Controller Name:         io.cilium/gateway-controller

* The gateway specified under ``parentRefs`` does not exist.

    To verify whether the gateway was found, run ``kubectl describe httproute <name>`` and inspect the ``conditions`` field:
   
.. code-block:: shell-session

  Parents:
    Conditions:
      Last Transition Time:  2023-06-06T13:56:40Z
      Message:               Gateway.gateway.networking.k8s.io "my-gatewai" not found
      Observed Generation:   2
        Reason:                InvalidHTTPRoute
        Status:                False
        Type:                  Accepted

Underlying mechanics: a high level overview
-------------------------------------------

A Cilium deployment has two parts that handle Gateway API resources: the Cilium agent and the Cilium operator.

The Cilium operator watches all Gateway API resources and verifies whether the resources are valid.
If resources are valid, the operator marks them as accepted. That starts the process of translation into Cilium Envoy Configuration resources.

The Cilium agent then picks up the Cilium Envoy Configuration resources.

The Cilium agent uses the resources to supply the configuration to the built in Envoy or the Envoy DaemonSet. Envoy handles traffic.