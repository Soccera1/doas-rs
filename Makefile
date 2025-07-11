BINARY := target/release/doas
DEST := /usr/local/bin/doas
LIBCLANG_PATH ?= /usr/lib/llvm/20/lib64

.PHONY: all install clean

all:
	LIBCLANG_PATH=$(LIBCLANG_PATH) cargo build --release

install:
	cp $(BINARY) $(DEST)
	chown root:root $(DEST)
	chmod u+s $(DEST)

clean:
	cargo clean
