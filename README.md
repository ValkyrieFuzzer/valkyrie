# Valkyrie

Valkyrie is a principled fuzzer based on [Angora](https://github.com/AngoraFuzzer/Angora).
Valkyrie provides a branch new branch counting method that combines the best of two worlds: it is not only collision free but also context sensitive.
A ground breaking work of Valkyrie is we also developed a compression algorithm at static time to reduce 70% of all branch count tables, and in turn reduced ~28% of the runtime.

Another contribution is a updated gradient solver that are more fitted to byte domain.
We find the previous work has unrealistic assumptions that the gradient descend works on real domain. 
Therefore, we develop an algorithm to move the numerical values that can't be represented in this byte to the next byte and call it compensated step.

## Building Valkyrie

### Build Requirements

- Linux-amd64 (Tested on Ubuntu 16.04/18.04 and Debian Buster)
- Rust stable (>= 1.55), can be obtained using [rustup](https://rustup.rs)
- [LLVM 11.0.0](http://llvm.org/docs/index.html) : run `PREFIX=/path-to-install ./build/install_llvm.sh`.

### Environment Variables

Append the following entries in the shell configuration file (`~/.bashrc`, `~/.zshrc`).

```
export PATH=/path-to-clang/bin:$PATH
export LD_LIBRARY_PATH=/path-to-clang/lib:$LD_LIBRARY_PATH
```

### Fuzzer Compilation

The build script will resolve most dependencies and setup the 
runtime environment.

```shell
./build/build.sh
```

### System Configuration

As with AFL, system core dumps must be disabled.

```shell
echo core | sudo tee /proc/sys/kernel/core_pattern
```

## Running Valkyrie

### Build Target Program

Valkyrie compiles the program into two separate binaries, each with their respective
instrumentation. Using `autoconf` programs as an example, here are the steps required.

```
# Use the instrumenting compilers
CC=/path/to/valkyrie/bin/angora-clang \
CXX=/path/to/valkyrie/bin/angora-clang++ \
LD=/path/to/valkyrie/bin/angora-clang \
PREFIX=/path/to/target/directory \
./configure --disable-shared

# Build with taint tracking support 
USE_TRACK=1 make -j
make install

# Save the compiled target binary into a new directory
# and rename it with .taint postfix, such as uniq.taint

# Build with light instrumentation support
make clean
USE_FAST=1 make -j
make install

# Save the compiled binary into the directory previously
# created and rename it with .fast postfix, such as uniq.fast

```

If you fail to build by this approach, try `wllvm` and `gllvm` described in [Build a target program](./docs/build_target.md#wllvm-or-gllvm).

Also, we have implemented taint analysis with libdft64 instead of DFSan ([Use libdft64 for taint tracking](./docs/pin_mode.md)). 
