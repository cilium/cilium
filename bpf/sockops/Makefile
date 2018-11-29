
FLAGS := -I../include -I. -I.. -D__NR_CPUS__=$(shell nproc) -O2 -g
CLANG_FLAGS :=  ${FLAGS} -target bpf -emit-llvm
CLANG_FLAGS += -Wall -Werror -Wno-address-of-packed-member -Wno-unknown-warning-option
LLC_FLAGS   := -march=bpf -mcpu=probe -mattr=dwarfris -filetype=obj


SOCKOPS_OPTIONS = \
	 -DSKIP_DEBUG \
	 -DHAVE_LPM_MAP_TYPE \
	 -DHAVE_LRU_MAP_TYPE

BPF = bpf_sockops.o bpf_redir.o
LIB := $(shell find ../ -name '*.h')

CLANG  ?= clang
LLC    ?= llc
HOSTCC ?= gcc

all: $(BPF)

bpf_sockops.o: bpf_sockops.c $(LIB)
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} ${SOCKOPS_OPTIONS} -c $< -o $(patsubst %.o,%.ll,$@)
	$(QUIET) ${LLC} ${LLC_FLAGS} -o $@ $(patsubst %.o,%.ll,$@)

bpf_redir.o: bpf_redir.c $(LIB)
	@$(ECHO_CC)
	$(QUIET) ${CLANG} ${CLANG_FLAGS} ${SOCKOPS_OPTIONS} -c $< -o $(patsubst %.o,%.ll,$@)
	$(QUIET) ${LLC} ${LLC_FLAGS} -o $@ $(patsubst %.o,%.ll,$@)

check:
	@$(ECHO_CHECK) bpf/*.c
	$(QUIET) spatch --sp-file ../contrib/coccinelle/null.cocci --dir . --include-headers
	$(QUIET) sparse -Wsparse-all ${FLAGS} *.c
	$(QUIET) $(CLANG) ${CLANG_FLAGS} --analyze *.c

preprocess: $(LIB)
	$(QUIET) $(foreach TARGET,$(shell find ./ -name 'bpf_*.c'), \
		echo "  GEN   ${TARGET}.i"; \
		${CLANG} $(FLAGS) -E -target bpf -c ${TARGET} -o ${TARGET}.i; )

install:
	$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

clean:
	@$(ECHO_CLEAN) $(notdir $(shell pwd))
	$(QUIET)rm -fr *.o *.ll *.i
	$(QUIET)rm -f $(TARGET)
