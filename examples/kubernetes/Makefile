include ../../Makefile.defs

ifeq ($(CILIUM_VERSION),)
    CILIUM_VERSION = "v$(shell cat ../../VERSION)"
endif

K8S_VERSIONS = 1.8 1.9 1.10 1.11 1.12 1.13

SOURCES = $(wildcard templates/v1/*.yaml*)
FILENAME_SOURCES = $(patsubst templates/v1/%,%,$(patsubst %.yaml.sed,%.yaml,$(SOURCES)))
CILIUM_CRIO_SOURCES = $(sort $(filter-out cilium-pre-flight.yaml cilium-ds.yaml,$(FILENAME_SOURCES)))
CILIUM_DOCKER_SOURCES = $(sort $(filter-out cilium-pre-flight.yaml cilium-crio-ds.yaml,$(FILENAME_SOURCES)))

all: transform cilium.yaml cilium-crio.yaml

%.sed:
	for k8s_version in $(K8S_VERSIONS); do \
	    (mkdir -p $$k8s_version && \
	    cd $$k8s_version && \
	    sed -f transforms2sed.sed ../templates/v1/$@ | \
	    sed s+__CILIUM_VERSION__+$(CILIUM_VERSION)+g > "$*"); \
	done

cilium-crio-ds.yaml.sed:
	for k8s_version in $(K8S_VERSIONS); do \
	    (mkdir -p $$k8s_version && \
	    cd $$k8s_version && \
	    if [ -f cilium-crio-transforms2sed.sed ]; then \
	        sed -f transforms2sed.sed ../templates/v1/$@ | \
	        sed -f cilium-crio-transforms2sed.sed | \
	        sed s+__CILIUM_VERSION__+$(CILIUM_VERSION)+g > "cilium-crio-ds.yaml"; \
	    else \
	        sed -f transforms2sed.sed ../templates/v1/$@ | \
	        sed s+__CILIUM_VERSION__+$(CILIUM_VERSION)+g > "cilium-crio-ds.yaml"; \
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
            for f in $(CILIUM_DOCKER_SOURCES); do (cat "$${f}") >> $@; done); \
	done

cilium-crio.yaml:
	for k8s_version in $(K8S_VERSIONS); do \
        (cd $$k8s_version && \
            rm -f ./$@ && \
            for f in $(CILIUM_CRIO_SOURCES); do (cat "$${f}") >> $@; done); \
	done

clean:
	for k8s_version in $(K8S_VERSIONS); do \
        rm ./$$k8s_version/*.yaml; \
	done

transform: cilium-rbac.yaml.sed \
    cilium-cm.yaml \
    cilium-crio-ds.yaml.sed \
    cilium-ds.yaml.sed \
    cilium-pre-flight.yaml.sed \
    cilium-rbac.yaml.sed \
    cilium-sa.yaml \
    cilium-operator.yaml.sed

.PHONY: transform cilium.yaml
