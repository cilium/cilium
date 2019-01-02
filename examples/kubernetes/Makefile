include ../../Makefile.defs

ifeq ($(CILIUM_VERSION),)
    CILIUM_VERSION = "v$(shell cat ../../VERSION)"
endif

CILIUM_INIT_VERSION = "2018-10-16"
CILIUM_ETCD_OPERATOR_VERSION = "v2.0.3"
K8S_VERSIONS = 1.8 1.9 1.10 1.11 1.12 1.13

COMMON = \
  cilium-cm.yaml \
  cilium-operator.yaml \
  cilium-operator-rbac.yaml \
  cilium-rbac.yaml

ETCD_OPERATOR= \
  cilium-etcd-operator-rbac.yaml \
  cilium-etcd-operator-sa.yaml \
  cilium-etcd-operator.yaml

CILIUM_DEFAULT= \
  cilium-ds.yaml \
  $(COMMON) \
  $(ETCD_OPERATOR)

CILIUM_MINIKUBE= \
  cilium-minikube-ds.yaml \
  cilium-cm.yaml \
  cilium-rbac.yaml

CILIUM_CRIO= \
  cilium-crio-ds.yaml \
  $(COMMON) \
  $(ETCD_OPERATOR)

all: transform cilium.yaml cilium-crio.yaml cilium-minikube.yaml

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

cilium-crio.yaml:
	for k8s_version in $(K8S_VERSIONS); do \
        (cd $$k8s_version && \
            rm -f ./$@ && \
            for f in $(CILIUM_CRIO); do (cat "$${f}") >> $@; done); \
	done

cilium-minikube.yaml:
	export __CILIUM_CONTAINER_RUNTIME__=auto
	for k8s_version in $(K8S_VERSIONS); do \
        (cd $$k8s_version && \
            rm -f ./$@ && \
            for f in $(CILIUM_MINIKUBE); do (cat "$${f}") >> $@; done; \
	sed -i 's+https://cilium-etcd-client.kube-system.svc:2379+https://127.0.0.1:2379+' cilium-minikube.yaml; \
	sed -i 's+/var/lib/etcd-secrets/etcd-client-ca.crt+/var/lib/etcd-secrets/etcd/ca.crt+' cilium-minikube.yaml; \
	sed -i 's+/var/lib/etcd-secrets/etcd-client.key+/var/lib/etcd-secrets/apiserver-etcd-client.key+' cilium-minikube.yaml; \
	sed -i 's+/var/lib/etcd-secrets/etcd-client.crt+/var/lib/etcd-secrets/apiserver-etcd-client.crt+' cilium-minikube.yaml); \
	done

clean:
	for k8s_version in $(K8S_VERSIONS); do \
        rm ./$$k8s_version/*.yaml; \
	done

transform: $(notdir $(wildcard templates/v1/*.sed) $(wildcard templates/v1/*.yaml))

.PHONY: transform cilium.yaml
