# -*- mode: Python -*-
source = load_dynamic('./Tiltfile.source')

helm_values = [
    # 'install/kubernetes/cilium/values/minikube.yaml',
    # 'install/kubernetes/cilium/values/kind.yaml',
    # 'install/kubernetes/cilium/values/aws/aws.yaml',
]

helm_sets = [
    'kubeProxyReplacement=strict',
    'securityContext.privileged=true',
    'nodeinit.enabled=true',
    'ipam.mode=kubernetes',
    'image.repository=cilium',
    'operator.replicas=1',
    'operator.image.repository=operator',
    'prometheus.enabled=true',
    'hubble.relay.enabled=true',
    'hubble.relay.prometheus.enabled=true',
    'hubble.ui.enabled=true',
    'hubble.peerService.enabled=false',
    'ingressController.enabled=true',
    'ingressController.loadbalancerMode=shared',
    'loadBalancer.l7.backend=envoy',
    'loadBalancer.l7.ports=8080',
    'loadBalancer.l7.algorithm=least_request',
    'gatewayAPI.enabled=true',
    'gatewayAPI.secretsNamespace.name=cilium-secrets-gateway',
    'debug.enabled=true',
    'debug.verbose=false',
]

# Local resources
local_resource('cilium-compile', 'make -j $(nproc) build', deps=source['cilium_source'],
               ignore=source['ignore_files'],
               labels=['build'])

local_resource('cilium-operator-compile', 'make -C operator -j $(nproc) cilium-operator-generic',
               deps=source['operator_source'],
               ignore=source['ignore_files'],
               labels=['build'])

# local_resource('hubble-relay-compile', 'make -j $(nproc) hubble-relay', deps=source['hubble_relay_source'],
#                ignore=source['ignore_files'],
#                labels=['build'])

# Generate helm template
k8s_yaml(helm('install/kubernetes/cilium', name='cilium', namespace='kube-system', values=helm_values,
              set=helm_sets))

# Docker build
docker_build('cilium', '.', dockerfile='images/cilium/Dockerfile.debug', only=source['cilium_source'])

docker_build('operator-generic-ci', '.', dockerfile='images/operator/Dockerfile.debug',
             build_args={
                 "OPERATOR_VARIANT": 'operator-generic',
             },
             entrypoint=['/usr/bin/cilium-operator-generic'],
             only=source['operator_source'],
             )

# Deployment manifest
k8s_resource(workload='cilium', resource_deps=['cilium-compile'], labels=['deployment'])
k8s_resource(workload='cilium-operator', resource_deps=['cilium-operator-compile'], labels=['deployment'])
# k8s_resource(workload='hubble-ui', port_forwards=8081)
