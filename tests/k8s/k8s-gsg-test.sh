#!/bin/bash

set -ex

NAMESPACE="kube-system" 
GOPATH="/home/vagrant/go"

source "../helpers.bash"
source /home/vagrant/.profile

MINIKUBE=../../examples/minikube
K8SDIR=../../examples/kubernetes

function cleanup {
	kubectl delete -f $MINIKUBE/l3_l4_l7_policy.yaml 2> /dev/null || true
	kubectl delete -f $MINIKUBE/l3_l4_policy.yaml 2> /dev/null || true
	kubectl delete -f $MINIKUBE/demo.yaml 2> /dev/null || true
	kubectl delete -f $K8SDIR/cilium-ds.yaml 2> /dev/null || true
	kubectl delete -f $K8SDIR/rbac.yaml 2> /dev/null || true
}

function gather_logs {
        mkdir -p ./cilium-files/logs
        kubectl logs -n kube-system $(kubectl -n kube-system get pods -l k8s-app=cilium | grep -v AGE | awk '{print $1}' ) > ./cilium-files/logs/cilium-logs
        kubectl logs -n kube-system kube-apiserver-vagrant > ./cilium-files/logs/kube-apiserver
        kubectl logs -n kube-system kube-controller-manager-vagrant > ./cilium-files/logs/kube-controller-manager-logs
        journalctl -au kubelet > ./cilium-files/logs/kubelet-logs
}

function finish_test {
        gather_files k8s-gsg-test ${TEST_SUITE}
        gather_logs
        cleanup
}

trap finish_test exit

echo "KUBECONFIG: $KUBECONFIG"

cleanup

wait_for_healthy_k8s_cluster 3

echo "----- adding RBAC for Cilium -----"
kubectl create -f $K8SDIR/rbac.yaml

echo "----- deploying Cilium Daemon Set onto cluster -----"
cp $K8SDIR/cilium-ds.yaml .
sed -i s/"\/var\/lib\/kubelet\/kubeconfig"/"\/etc\/kubernetes\/kubelet.conf"/g cilium-ds.yaml
sed -i s/"cilium\/cilium:stable"/"localhost:5000\/cilium:${DOCKER_IMAGE_TAG}"/g cilium-ds.yaml
kubectl create -f cilium-ds.yaml

wait_for_daemon_set_ready ${NAMESPACE} cilium 1

CILIUM_POD=$(kubectl -n ${NAMESPACE} get pods -l k8s-app=cilium | grep -v 'AGE' | awk '{ print $1 }')
wait_for_kubectl_cilium_status ${NAMESPACE} ${CILIUM_POD}

echo "----- deploying demo application onto cluster -----"
kubectl create -f $MINIKUBE/demo.yaml

wait_for_n_running_pods 4

echo "----- adding L3 L4 policy  -----"
kubectl create -f $MINIKUBE/l3_l4_policy.yaml

wait_for_k8s_endpoints kube-system ${CILIUM_POD} 5

echo "----- testing L3/L4 policy -----"
APP2_POD=$(kubectl get pods -l id=app2 -o jsonpath='{.items[0].metadata.name}')
SVC_IP=$(kubectl get svc app1-service -o jsonpath='{.spec.clusterIP}' )

echo "----- testing app2 can reach app1 (expected behavior: can reach) -----"
RETURN=$(kubectl $ID exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET $SVC_IP || true)
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "Error: could not reach pod allowed by L3 L4 policy"
fi

echo "----- testing that app3 cannot reach app 1 (expected behavior: cannot reach)"
APP3_POD=$(kubectl get pods -l id=app3 -o jsonpath='{.items[0].metadata.name}')
RETURN=$(kubectl exec $APP3_POD -- curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 -XGET $SVC_IP || true)
if [[ "${RETURN//$'\n'}" != "000" ]]; then
	abort "Error: unexpectedly reached pod allowed by L3 L4 Policy, received return code ${RETURN}"
fi

echo "------ performing HTTP GET on ${SVC_IP}/public from service2 ------"
RETURN=$(kubectl exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 http://${SVC_IP}/public || true)
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "Error: Could not reach ${SVC_IP}/public on port 80"
fi

echo "------ performing HTTP GET on ${SVC_IP}/private from service2 ------"
RETURN=$(kubectl exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 http://${SVC_IP}/private || true)
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "Error: Could not reach ${SVC_IP}/public on port 80"
fi

echo "----- creating L7-aware policy -----"
kubectl create -f $MINIKUBE/l3_l4_l7_policy.yaml

echo "----- Waiting for endpoints to get into 'ready' state -----"
CILIUM_POD=$(kubectl -n ${NAMESPACE} get pods -l k8s-app=cilium | grep -v 'AGE' | awk '{ print $1 }')
until [ "$(kubectl -n ${NAMESPACE} exec ${CILIUM_POD} cilium endpoint list | grep -c 'ready')" -eq "5" ]; do
  continue
done

echo "------ performing HTTP GET on ${SVC_IP}/public from service2 ------"
RETURN=$(kubectl exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 http://${SVC_IP}/public || true)
if [[ "${RETURN//$'\n'}" != "200" ]]; then
	abort "Error: Could not reach ${SVC_IP}/public on port 80"
fi

echo "------ performing HTTP GET on ${SVC_IP}/private from service2 ------"
RETURN=$(kubectl exec $APP2_POD -- curl -s --output /dev/stderr -w '%{http_code}' --connect-timeout 10 http://${SVC_IP}/private || true)
if [[ "${RETURN//$'\n'}" != "403" ]]; then
	abort "Error: Unexpected success reaching  ${SVC_IP}/private on port 80"
fi

echo "------ L7 policy success ! ------"
