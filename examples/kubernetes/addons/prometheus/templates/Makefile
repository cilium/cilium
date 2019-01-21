include ../../../../../Makefile.defs


DESTINATION= "../monitoring-example.yaml"

create: clean
	for file in $(shell ls -1 *.yaml); do \
		cat $$file >> $(DESTINATION); \
	done

clean:
	rm $(DESTINATION)

.PHONY: create
