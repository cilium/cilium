# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright Authors of Cilium

include ../../Makefile.defs

.PHONY: all clean

BASE_PROG := bpf_custom.c

ifneq ("$(BPF_CUSTOM_PROG_FILE)", "")
PROGS = $(patsubst %.h,%.o,$(BPF_CUSTOM_PROG_FILE))
else
# If no header file was passed, compile for all header files found in the
# directory.
PROGS = $(patsubst %.h,%.o,$(wildcard *.h))
endif

ifneq ("$(BPF_CUSTOM_PROG_NAME)","")
sec_name = $(BPF_CUSTOM_PROG_NAME)
else
sec_name = $(basename $(1))
endif

include ../Makefile.bpf

all: $(PROGS)

%.ll: %.h $(BASE_PROG) $(LIB)
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} \
		-DBPF_CUSTOM_PROG_FILE=$< \
		-DBPF_CUSTOM_PROG_NAME=$(call sec_name,$<) \
		-c $(BASE_PROG) -o $@

$(PROGS): %.o: %.ll
	@$(ECHO_CC)
	$(QUIET) ${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -fr *.o *.ll *.i
