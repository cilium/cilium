# Policy Example: Kubernetes ServiceAccounts

A simple policy example how to match on Kubernetes ServiceAccount names.

## Deploy the demo application

        $ kubectl create -f demo-pods.yaml
        serviceaccount "leia" created
        serviceaccount "luke" created
        serviceaccount "vader" created
        deployment.extensions "leia-deployment" created
        service "leia" created
        pod "luke-pod" created
        pod "vader-pod" created

        $ kubectl get sa
        NAME      SECRETS   AGE
        default   1         1d
        leia      1         16m
        luke      1         16m
        vader     1         16m

## Review and deploy the policy

The following policy allows pods launched by ServiceAccount "luke" to
communicate with pods launched by ServiceAccount "leia":

        cat serviceaccount-policy.yaml
        apiVersion: "cilium.io/v2"
        kind: CiliumNetworkPolicy
        metadata:
          name: "k8s-svc-account"
        spec:
          endpointSelector:
            matchLabels:
              io.cilium.k8s.policy.serviceaccount: leia
          ingress:
          - fromEndpoints:
            - matchLabels:
                io.cilium.k8s.policy.serviceaccount: luke


        kubectl create -f serviceaccount-policy.yaml
        ciliumnetworkpolicy.cilium.io "k8s-svc-account" created

## Test the policy

As "luke-pod" is bound to ServiceAccount "luke", the request is allowed:

        kubectl exec -ti luke-pod curl leia.default.svc.cluster.local/v1/
        {
                "name": "Death Star",
                "model": "DS-1 Orbital Battle Station",
                "manufacturer": "Imperial Department of Military Research, Sienar Fleet Systems",
                "cost_in_credits": "1000000000000",

As "vader-pod" is bound to ServiceAccount "vader", the request is rejected:

        kubectl exec -ti vader-pod curl leia.default.svc.cluster.local/v1/
        [ ... timeout ... ]
