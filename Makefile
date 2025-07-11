BINARY := target/release/doas
DEST := /usr/local/bin/doas
LIBCLANG_PATH ?= /usr/lib/llvm/20/lib64

.PHONY: all install clean uninstall

all:
	LIBCLANG_PATH=$(LIBCLANG_PATH) cargo build --release

install:
	cp $(BINARY) $(DEST)
	chown root:root $(DEST)
	chmod u+s $(DEST)

uninstall:
	rm -f $(DEST)

clean:
	cargo clean