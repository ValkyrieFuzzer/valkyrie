BUILD_TYPE="debug"
# BUILD_TYPE="release"
LOG_TYPE=angora
MODE="llvm"
ENVS="BUILD_TYPE=${BUILD_TYPE} LOG_TYPE=${LOG_TYPE}"

all: driver dummy_fuzz dummy_fuzz_bc dummy_fuzz_fast dummy_fuzz_taint test

libdummy: dummy.cc
	~/go/bin/gclang++ -g -O0 -c dummy.cc -fPIC -o libdummy.a

driver: valkyrie_driver.c
	~/go/bin/gclang -g -O0 -c "valkyrie_driver.c" -fPIC -o valkyrie_driver.o

dummy_fuzz: dummy_fuzz.cc libdummy driver
	~/go/bin/gclang++ -g -O0 "dummy_fuzz.cc" libdummy.a valkyrie_driver.o -fPIC -o dummy_fuzz

dummy_fuzz_bc: driver dummy_fuzz
	~/go/bin/get-bc dummy_fuzz
	opt -break-crit-edges dummy_fuzz.bc -o dummy_fuzz.bc
dummy_fuzz_fast: dummy_fuzz_bc
	USE_FAST=1 ../../bin/angora-clang++ dummy_fuzz.bc -lz -lrt -o dummy_fuzz.fast
dummy_fuzz_taint: dummy_fuzz_bc
	USE_TRACK=1 ../../bin/angora-clang++ dummy_fuzz.bc -lz -lrt -o dummy_fuzz.taint

test: dummy_fuzz_fast dummy_fuzz_taint
	rm ../output -rf
	../../angora_fuzzer -M 0 -A -i ../input -o ../output -m llvm -t ./dummy_fuzz.taint -- ./dummy_fuzz.fast