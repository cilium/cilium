.. note::

    The following commands use the ``-P`` (``--port-forward``) flag to automatically
    port-forward the Hubble Relay service from your local machine on port ``4245``.

    You can also omit the flag and create a port-forward manually with the Cilium CLI:

    .. code-block:: shell-session

        $ cilium hubble port-forward
        ℹ️ Hubble Relay is available at 127.0.0.1:4245

    Or with kubectl:

    .. code-block:: shell-session

        $ kubectl -n kube-system port-forward service/hubble-relay 4245:80
        Forwarding from 127.0.0.1:4245 -> 4245
        Forwarding from [::1]:4245 -> 4245

    For more information on this method, see `Use Port Forwarding to Access Application in a Cluster <https://kubernetes.io/docs/tasks/access-application-cluster/port-forward-access-application-cluster/>`_.
