Deploy the Echo App
===================

We will use a deployment made of echo servers.

The application will reply to the client and, in the body of the reply, will include information about the Pod and Node receiving the original request. 
We will use this information to illustrate how the traffic is manipulated by the Gateway. 

.. parsed-literal::

    $ kubectl apply -f \ |SCM_WEB|\/examples/kubernetes/gateway/echo.yaml

Verify the Pods are running as expected. 

.. code-block:: shell-session

    $ kubectl get pods
    NAME                      READY   STATUS    RESTARTS   AGE
    echo-1-7d88f779b-m6r46    1/1     Running   0          21s
    echo-2-5bfb6668b4-n7llh   1/1     Running   0          21s

