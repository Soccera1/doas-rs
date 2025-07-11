# what is this
i just wanted to practice rust so i decided to rewrite doas in rust
please dont use this




how to install:

1. clone this repo

2. run the following commands:

```sh
$ make

# make install
```

how to uninstall:

```sh
# rm /usr/local/bin/doas
```


### notes
you might need to set LIBCLANG_PATH if the build fails:

```sh
export LIBCLANG_PATH=/usr/lib/llvm/20/lib64
```

