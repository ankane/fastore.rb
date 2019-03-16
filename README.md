# FastORE.rb

[FastORE](https://github.com/kevinlewi/fastore) for Ruby

## Installation

Download [FastORE](https://github.com/kevinlewi/fastore#installation) and this repo

```sh
git clone --recursive https://github.com/kevinlewi/fastore.git
git clone https://github.com/ankane/fastore.rb.git
```

For Homebrew on Mac, update `Makefile` to use Homebrew OpenSSL:

```sh
INCPATHS = -I/usr/local/opt/openssl/include -I/usr/local/include
LDPATH = -L/usr/local/opt/openssl/lib -L/usr/local/lib
```

And replace `<malloc.h>` with `<stdlib.h>` in `ore_blk.c`.

Compile with:

```sh
cd fastore
make
```

Then create shared objects:

```sh
cd build
gcc -shared -o ore.so ore.o crypto.o -lgmp -lssl -lcrypto
gcc -shared -o ore_blk.so ore_blk.o crypto.o -lgmp -lssl -lcrypto
cp *.so ../../fastore.rb
```

## Tests

```sh
ruby test_ore.rb
ruby test_ore_blk.rb
```
