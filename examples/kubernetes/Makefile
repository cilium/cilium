include ../../Makefile.defs

ifeq ($(CILIUM_VERSION),)
    CILIUM_VERSION = "$(shell cat ../../VERSION)"
endif

all: transform cilium.yaml

%.sed:
	for k8s_version in 1.7 1.8 1.9 1.10 1.11; do \
	    (mkdir -p $$k8s_version && \
	    cd $$k8s_version && \
	    sed -f transforms2sed.sed ../templates/v1/$@ | \
	    sed s+__CILIUM_VERSION__+$(CILIUM_VERSION)+g > "$*"); \
	done

%.yaml:
	for k8s_version in 1.7 1.8 1.9 1.10 1.11; do \
	    (mkdir -p $$k8s_version && \
	    cd $$k8s_version && \
	    cp ../templates/v1/$@ $@); \
	done

cilium.yaml:
	for k8s_version in 1.7 1.8 1.9 1.10 1.11; do \
        (cd $$k8s_version && \
            rm -f ./$@ && \
            for f in *.yaml; do (cat "$${f}"; echo "---") >> $@; done); \
	done

clean:
	for k8s_version in 1.7 1.8 1.9 1.10 1.11; do \
        rm ./$$k8s_version/*.yaml; \
	done

transform: cilium-ds.yaml.sed cilium-rbac.yaml.sed cilium-cm.yaml cilium-sa.yaml

.PHONY: transform cilium.yaml
