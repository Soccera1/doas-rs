BINARY := target/release/doas
DEST := /usr/local/bin/doas

.PHONY: all install clean

all:
	cargo build --release

install:
	cp $(BINARY) $(DEST)
	chown root:root $(DEST)
	chmod u+s $(DEST)

clean:
	cargo clean
