include ../../Makefile.defs

ifeq ($(CILIUM_VERSION),)
    CILIUM_VERSION = "v$(shell cat ../../VERSION)"
endif

CILIUM_INIT_VERSION = "2018-10-16"
CILIUM_ETCD_OPERATOR_VERSION = "v2.0.5"
K8S_VERSIONS = 1.8 1.9 1.10 1.11 1.12 1.13

ETCD_OPERATOR= \
  cilium-etcd-operator-rbac.yaml \
  cilium-etcd-operator-sa.yaml \
  cilium-etcd-operator.yaml

CILIUM_DEFAULT= \
  cilium-cm.yaml \
  cilium-ds.yaml \
  cilium-operator.yaml \
  cilium-operator-sa.yaml \
  $(ETCD_OPERATOR) \
  cilium-rbac.yaml

CILIUM_NODE_INIT= \
  cilium-cm.yaml \
  cilium-ds.yaml \
  cilium-operator.yaml \
  cilium-operator-sa.yaml \
  $(ETCD_OPERATOR) \
  cilium-rbac.yaml

CILIUM_EXTERNAL_ETCD= \
  cilium-cm.yaml \
  cilium-ds.yaml \
  cilium-operator.yaml \
  cilium-operator-sa.yaml \
  cilium-rbac.yaml

CILIUM_MINIKUBE= \
  cilium-cm.yaml \
  cilium-minikube-ds.yaml \
  cilium-rbac.yaml

CILIUM_CRIO= \
  cilium-cm.yaml \
  cilium-crio-ds.yaml \
  cilium-operator.yaml \
  cilium-operator-sa.yaml \
  $(ETCD_OPERATOR) \
  cilium-rbac.yaml

CILIUM_CONTAINERD= \
  cilium-cm.yaml \
  cilium-containerd-ds.yaml \
  cilium-operator.yaml \
  cilium-operator-sa.yaml \
  $(ETCD_OPERATOR) \
  cilium-rbac.yaml

all: transform cilium.yaml cilium-crio.yaml cilium-containerd.yaml cilium-minikube.yaml cilium-external-etcd.yaml cilium-with-node-init.yaml

%.sed:
	for k8s_version in $(K8S_VERSIONS); do \
	    (mkdir -p $$k8s_version && \
	    cd $$k8s_version && \
	    sed -f transforms2sed.sed ../templates/v1/$@ | \
	    sed s+__CILIUM_VERSION__+$(CILIUM_VERSION)+g | \
	    sed s+__CILIUM_INIT_VERSION__+$(CILIUM_INIT_VERSION)+g | \
	    sed s+__CILIUM_ETCD_OPERATOR_VERSION__+$(CILIUM_ETCD_OPERATOR_VERSION)+g > "$*"); \
	done

cilium-crio-ds.yaml.sed:
	for k8s_version in $(K8S_VERSIONS); do \
	    (mkdir -p $$k8s_version && \
	    cd $$k8s_version && \
	    if [ -f cilium-crio-transforms2sed.sed ]; then \
	        sed -f transforms2sed.sed ../templates/v1/$@ | \
	        sed -f cilium-crio-transforms2sed.sed | \
	        sed s+__CILIUM_VERSION__+$(CILIUM_VERSION)+g | \
	        sed s+__CILIUM_INIT_VERSION__+$(CILIUM_INIT_VERSION)+g | \
	        sed s+__CILIUM_ETCD_OPERATOR_VERSION__+$(CILIUM_ETCD_OPERATOR_VERSION)+g > "cilium-crio-ds.yaml"; \
	    else \
	        sed -f transforms2sed.sed ../templates/v1/$@ | \
	        sed s+__CILIUM_VERSION__+$(CILIUM_VERSION)+g | \
	        sed s+__CILIUM_INIT_VERSION__+$(CILIUM_INIT_VERSION)+g | \
	        sed s+__CILIUM_ETCD_OPERATOR_VERSION__+$(CILIUM_ETCD_OPERATOR_VERSION)+g > "cilium-crio-ds.yaml"; \
	    fi); \
	done

cilium-containerd-ds.yaml.sed:
	for k8s_version in $(K8S_VERSIONS); do \
	    (mkdir -p $$k8s_version && \
	    cd $$k8s_version && \
	        sed -f transforms2sed.sed ../templates/v1/$@ | \
	        sed s+__CILIUM_VERSION__+$(CILIUM_VERSION)+g | \
	        sed s+__CILIUM_INIT_VERSION__+$(CILIUM_INIT_VERSION)+g | \
	        sed s+__CILIUM_ETCD_OPERATOR_VERSION__+$(CILIUM_ETCD_OPERATOR_VERSION)+g > "cilium-containerd-ds.yaml"; \
	    ); \
	done

%.yaml:
	for k8s_version in $(K8S_VERSIONS); do \
	    (mkdir -p $$k8s_version && \
	    cd $$k8s_version && \
	    cp ../templates/v1/$@ $@); \
	done

cilium.yaml:
	for k8s_version in $(K8S_VERSIONS); do \
        (cd $$k8s_version && \
            rm -f ./$@ && \
            for f in $(CILIUM_DEFAULT); do (cat "$${f}") >> $@; done); \
	done

cilium-with-node-init.yaml:
	export __CILIUM_CONTAINER_RUNTIME__=auto
	for k8s_version in $(K8S_VERSIONS); do \
        (cd $$k8s_version && \
            rm -f ./$@ && \
            for f in $(CILIUM_NODE_INIT); do (cat "$${f}") >> $@; done; \
	    sed -i 's+namespace: kube-system+namespace: cilium+' cilium-with-node-init.yaml; \
	    sed -i '/priorityClassName: system-node-critical/d' cilium-with-node-init.yaml; \
	    sed -i 's+path: /opt/cni/bin+path: /home/kubernetes/bin+' cilium-with-node-init.yaml; \
	    sed -i 's+https://cilium-etcd-client.kube-system.svc:2379+https://cilium-etcd-client.cilium.svc:2379+' cilium-with-node-init.yaml); \
	done

cilium-external-etcd.yaml:
	export __CILIUM_CONTAINER_RUNTIME__=auto
	for k8s_version in $(K8S_VERSIONS); do \
        (cd $$k8s_version && \
            rm -f ./$@ && \
            for f in $(CILIUM_EXTERNAL_ETCD); do (cat "$${f}") >> $@; done; \
	sed -i 's+https://cilium-etcd-client.kube-system.svc:2379+http://EDIT-ME-ETCD-ADDRESS:2379+' cilium-external-etcd.yaml; \
	sed -i "s+ca-file: '/var/lib/etcd-secrets/etcd-client-ca.crt'+# ca-file: '/var/lib/etcd-secrets/etcd-client-ca.crt'+" cilium-external-etcd.yaml; \
	sed -i "s+key-file: '/var/lib/etcd-secrets/etcd-client.key'+# key-file: '/var/lib/etcd-secrets/etcd-client.key'+" cilium-external-etcd.yaml; \
	sed -i "s+cert-file: '/var/lib/etcd-secrets/etcd-client.crt'+# cert-file: '/var/lib/etcd-secrets/etcd-client.crt'+" cilium-external-etcd.yaml); \
	done

cilium-crio.yaml:
	for k8s_version in $(K8S_VERSIONS); do \
        (cd $$k8s_version && \
            rm -f ./$@ && \
            for f in $(CILIUM_CRIO); do (cat "$${f}") >> $@; done); \
	done

cilium-containerd.yaml:
	for k8s_version in $(K8S_VERSIONS); do \
        (cd $$k8s_version && \
            rm -f ./$@ && \
            for f in $(CILIUM_CONTAINERD); do (cat "$${f}") >> $@; done); \
	done

cilium-minikube.yaml:
	export __CILIUM_CONTAINER_RUNTIME__=auto
	for k8s_version in $(K8S_VERSIONS); do \
        (cd $$k8s_version && \
            rm -f ./$@ && \
            for f in $(CILIUM_MINIKUBE); do (cat "$${f}") >> $@; done; \
            if [[ "$$k8s_version" == "1.8" || "$$k8s_version" == "1.9" ]]; then \
            sed -i 's+https://cilium-etcd-client.kube-system.svc:2379+http://127.0.0.1:2379+' cilium-minikube.yaml; \
            sed -i 's+ca-file:+# ca-file:+' cilium-minikube.yaml; \
            sed -i 's+key-file:+# key-file:+' cilium-minikube.yaml; \
            sed -i 's+cert-file:+# cert-file:+' cilium-minikube.yaml; \
            else \
            sed -i 's+https://cilium-etcd-client.kube-system.svc:2379+https://127.0.0.1:2379+' cilium-minikube.yaml; \
            sed -i 's+/var/lib/etcd-secrets/etcd-client-ca.crt+/var/lib/etcd-secrets/etcd/ca.crt+' cilium-minikube.yaml; \
            sed -i 's+/var/lib/etcd-secrets/etcd-client.key+/var/lib/etcd-secrets/apiserver-etcd-client.key+' cilium-minikube.yaml; \
            sed -i 's+/var/lib/etcd-secrets/etcd-client.crt+/var/lib/etcd-secrets/apiserver-etcd-client.crt+' cilium-minikube.yaml; \
            fi); \
            done

clean:
	for k8s_version in $(K8S_VERSIONS); do \
        rm ./$$k8s_version/*.yaml; \
	done

transform: $(notdir $(wildcard templates/v1/*.sed) $(wildcard templates/v1/*.yaml))

.PHONY: transform cilium.yaml
