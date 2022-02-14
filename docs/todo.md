## TODO

TODO(sorted by priority):

- Run magma(possibly unifuzz) for 1 hr, see if it works
    - ~~openssl and poppler programs halted, probably fast segfault so forkserver never started.~~
        - Solved using black listing. ~~openssl: crypto/cryptlib.c:104 shouldn't be instrumented by AngoraPass, it's in abilist.~~
            - AngoraPass don't care about abilist, worst, main is in dfsan's abilist, no idea how this works.
            - __branch_count_sub_table_ptr is derererenced in crypto/cryptlib.c:104, which is not setup yet.
        - Solved when moving init code to before main. ~~poppler: cpp init function with libcxx compiled by us seg fault. (But angora's fine)~~
    - ~~100M memory limit(`-M 100` in `$FUZZER/run.sh`) is not enough for `libc`, use at least 200. php: Fast can run, still forkserver are dead, need more work, angora's dead too.~~
        - `error while loading shared libraries: libc.so.6: failed to map segment from shared object`
    - ~~Programs based on `LLVMFuzzerTestOneInput` has no taint.~~
    (libxml2_xml_read_memory_fuzzer, tiff_read_rgba_fuzzer, libpng_read_fuzzer, sqlite3_fuzz)
    `__dfsw_read` is instrumented, but in assembly it dropped back to `read@plt` and thus everything had no taint.
    Actually, all libc functions are replaced to non-instrumenting ones.
        - This is caused by `instrument.sh`, where it tries to collect `abilist.txt`, but failed since `libc-2.27` is not in the blacklist(`libc` is in it.) 
        The temp fix is to add it to blacklist. But in the future we may have other libraries that have version numbers behind it.
    - ~~openssl, poppler and php programs has no taint, seems the same reason as above~~
    - ~~poppler still has no taint.~~
        - `pread64`, `sscanf` and `atoi` is not taintted. `pread64` is a wrapper to `pread`. What do we do about `atoi` and `sscanf`?
    - **Everything ran for 1 hr normally. Hooray!**
- Performance fixes, previous bugs removal.
    - ~~What's causing inconsistency between `track` and `trace`(`executor.rs:126`)?~~
        - Cause: `track` found a cond. When running `trace` for the first time(`ln 128`), it's not reachable(`ln 127`).
        This is an odd condition, because if `track` reached the cond, `trace` should too.
        - Angora has way fewer inconsistency than valkyrie.
        - Cause: the execution path is the same, but the context is not, thus the difference.
        - Root cause: ctx is randomly generated, random seed is a hash of module name, module name is different. 
            - `/magma_out/valkyrie-track/../bc/<PROGRAM>.bc` vs `/magma_out/valkyrie-track/../bc/<PROGRAM>.bc`
        - Fix: I'd like to fix all random seed to `0`, but for now only when `is_bc` is `true` do we use 0 seed.
        - It's a tricky bug and not shown unless we `fast` and `track` has different module name, which we assumed wouldn't happen when using bc.
    - `atoi`
        - ~~Model using `strtol` family.~~
        - Test
    - ~~Remove unwanted `__branch_count_table_ptr` and `__branch_count_sub_table_ptr`.~~
    - Should newgd restart on 0 gradient?(See the restart loop in `newgd.rs:188`)
    - ~~Unit test `mini` can pass, but not `mini2`. Essentially they are the same conditions(`x > 12300` and `x - 12300 > 0`), why the difference?~~ 
        - We should set add/sub one value to `f64::INFINTY` when it's not reachable.
    - ~~Length fix. See `cond_stmt/output.rs:40`. After we switch to `i128`, the semantics of `output()` changed.~~
    - ~~Branch counting pass is instrumenting the branches we instrumented.~~
    - Check if we have other functions that should be modelled and ignored by `instrument.sh`'s abi collection.
        - `mbtowc`, `strtok_r` is not modelled. Do we need to?
    - ~~Fix solver bugs and other bugs we fixed earlier~~
    - Figure out why llvm adds conflicting attributes to `dfsan_and_ins` that caused LTO to stop compile.
    - `trace_cmp` has a if branch. Currently it's instrumented using llvm, should we move it to rust using [`std::intrinsics::likely`](https://doc.rust-lang.org/std/intrinsics/fn.likely.html). To do this we probably need LTO and inline `trace_cmp` for better performance.
    - Add github ci
- Run magma for 24 hrs, compare Angora and Valkyrie
    - `AAH022`, `AAH020`, `AAH013` can be found and solved by angora, but not by valkyrie. Valkyrie didn't find `AAH013`.
- (Switch to a new branch and tag llvm11.1.0 as working)
    - Verify branch counting's correctness.
        - The branch count table size is wrong.
            - ~~Global table size doubled.~~ Because global table forgot that trace is u16, thus the size should divide 2.
            - main table is doubled.
        - The optimization on `switch3` is wrong too. Maybe other optimization is wrong?
        - `switch3` can't be solved correctly.
    - ~~Verify sign at runtime.~~
        - ~~If conflict or not sure, random.~~
        - Problem: if there is a const shift, `x + 1`, the inference would be accurate.
        - ~~Do more testing.~~
- new branch `exploiting`
    - Int explore
        - `infer_type` can't solve because of overflow caused local minima.
        - ~~Tested `div*`.~~
    - Mem explore
        - Performance notes: in `libpng`, explore has ~3000 predicates, exploit has ~30000
    - Ptr explore
        - test `array` is not passing, asan is not reporting OOB.
- Run magma for 24 hr, compare Angora, valkyrie, valkyrie-exp
    - div-by-zero: 
        - **`AAH001`**: Solved
        - `AAH011`(cmpid 52595)
        - `AAH050` because we have seed filter, nothing bigger than 15000 bytes gets through. It's in `issue6231_1.pdf`(23748 bytes). Taint tracking took 10+ minutes.
        - `AAH042`: Found but not triggered. Truncated from float. Has 100+ bytes of taints.
        - `JCH212`: Found but not triggered. Has 65 ~ 100+ bytes of taints.
            `poppler` runs very slow, takes about 10 minute to finish executing all seeds.
            Execution throughput is about 5 iterations per second. cmpid is `74612`. 
            Most seeds are discarded by valkyrie: "Seed discarded, too long: ..."
            Max file length is set to 15000 bytes in `MAX_INPUT_LEN`, which is a very tight bound on pdf files...
            3 minute for largest file on track version v.s. 8 seconds for asan version
            Condition for the big switch in `poppler/Lexer.cc:Lexer::getObj` seems to appear a lot.

    - (ma|re)alloc: 
        - `JCH227`, `AAH043`: not found, afl/afl++ found not solved.
        - `MAE115`: valkyrie solved, valkyrie-exp can't.
        - ~~`MAE113`~~, ~~`AAH028`~~: no one found, according to paper, no POV.
        - `AAH057`, ~~`AAH005`~~: found not solved
        - `AAH022`: only valkyrie(-exp) can't solve
        - **`AAH015`**: Solved.

    - Integer error: ~~`AAH004`, `AAH005`, `AAH028`~~, `AAH051`, `JCH202`, `JCH210`, ~~`MAE100`, `MAE102`~~, `MAE105`, ~~`MAE020`~~
        - ~~`AAH004`, `AAH005`~~: Seems nested and infeasiable. There is no PoC too. No fuzzer can solve it.
    - Angora solved but we didn't:
        - `AAH022`
        - `AAH013`
- (Add another tag as experiment)
- Function Splitting if necessary, then add another tag as experiment
- Split AngoraPass to multiple independ passes, preserve AngoraPass
to order all passes.
- Code hygiene