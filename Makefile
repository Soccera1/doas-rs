BINARY := target/release/doas
DEST := /usr/local/bin/doas-rs
MANPAGE := doas.1.gz
MANDIR := /usr/share/man/man1
LIBCLANG_PATH ?= /usr/lib/llvm/20/lib64

.PHONY: all install clean uninstall

all:
	LIBCLANG_PATH=$(LIBCLANG_PATH) cargo build --release

install:
	cp $(BINARY) $(DEST)
	chown root:root $(DEST)
	chmod u+s $(DEST)
	install -Dm644 $(MANPAGE) $(MANDIR)/doas.1.gz

uninstall:
	rm -f $(DEST)
	rm -f $(MANDIR)/doas.1.gz

clean:
	cargo clean
