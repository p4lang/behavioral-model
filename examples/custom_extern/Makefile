P4_PROGRAM := example
P4_JSON = $(P4_PROGRAM).json

P4C = p4c-bm2-ss
P4C_ARGS = --emit-externs

EXTERN_DIR = extern_lib
EXTERN_LIB = $(EXTERN_DIR)/definition.so

.PHONY: build start test stop clean

build: $(P4_JSON) $(EXTERN_LIB)

%.json: %.p4
	$(P4C) $(P4C_ARGS) -o $@ $<

$(EXTERN_LIB):
	cd $(EXTERN_DIR) && $(MAKE)

start: build
	sudo tools/veth_setup.sh
	sudo simple_switch -i 0@veth0 -i 1@veth2 $(P4_JSON) \
		-- --load-modules=$(EXTERN_LIB)

test:
	sudo python3 test.py

stop:
	sudo tools/veth_teardown.sh

clean:
	rm -f $(P4_PROGRAM)
	cd $(EXTERN_DIR) && $(MAKE) clean
