# File source
# https://raw.githubusercontent.com/kubernetes/kubernetes/release-1.23/cluster/addons/dns/coredns/coredns.yaml.base

apiVersion: v1
kind: Service
metadata:
  name: kube-dns
  namespace: kube-system
  annotations:
    prometheus.io/port: "9153"
    prometheus.io/scrape: "true"
  labels:
    k8s-app: kube-dns
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
    kubernetes.io/name: "CoreDNS"
spec:
  selector:
    k8s-app: kube-dns
  ipFamilyPolicy: "PreferDualStack"
  ipFamilies:
    - IPv4
    - IPv6
  clusterIP: $DNS_SERVER_IP
  clusterIPs:
  - $DNS_SERVER_IP
  - $DNS_SERVER_IPV6
  ports:
  - name: dns
    port: 53
    protocol: UDP
  - name: dns-tcp
    port: 53
    protocol: TCP
  - name: metrics
    port: 9153
    protocol: TCP
