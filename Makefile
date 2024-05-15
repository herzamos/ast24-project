CC = gcc
CFLAGS = -Iinclude/ -O0 -g
PWD = $(shell pwd)
TESTS = ${PWD}/tests
TARGETS = $(wildcard $(TESTS)/*)
RELATIVE_TARGETS = $(patsubst $(TESTS)/%,%,$(TARGETS))

define build_c
	@echo "Compiling $(1).c"
	$(CC) $(CFLAGS) "${TESTS}/$(1)/$(1).c" -o ${TESTS}/$(1)/$(1)
endef

define create_trace
	@echo "Creating trace for $(1)"
	${PWD}/pin/pin -t MyPinTool/obj-intel64/MyPinTool.so -- ${TESTS}/$(1)/$(1) &>$(TESTS)/$(1)/$(1).log
	mv out.trace "${TESTS}/$(1)/$(1).trace"
endef

define create_graph
	@echo "Creating graph for $(1)"
	cd "${PWD}/vecspot"; cargo run -- ${TESTS}/$(1)/$(1).trace; mv out.png $(TESTS)/$(1)/$(1).png
endef

pin_tool:
	@echo "${PWD}"
	cd "${PWD}/MyPinTool"; make PIN_ROOT="../pin" obj-intel64/MyPinTool.so -j8

all: $(RELATIVE_TARGETS)

$(RELATIVE_TARGETS): pin_tool
	$(call build_c,$@)
	$(call create_trace,$@)
	$(call create_graph,$@)

clean: $(addprefix clean_,$(RELATIVE_TARGETS))

realclean: $(addprefix realclean_,$(RELATIVE_TARGETS))

$(foreach name,$(RELATIVE_TARGETS),$(eval clean_$(name):; rm -f $(TESTS)/$(name)/$(name){,.trace,.log}))
$(foreach name,$(RELATIVE_TARGETS),$(eval realclean_$(name):; rm -f $(TESTS)/$(name)/$(name){,.trace,.png,.log}))