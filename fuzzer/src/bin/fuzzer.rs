#[macro_use]
extern crate clap;
use clap::{App, Arg};

extern crate angora;
extern crate angora_common;
use angora::fuzz_main;
use angora_common::config::{FuzzerConfig, CONFIG};

fn main() {
    let matches = App::new("angora-fuzzer")
        .version(crate_version!())
        .about("Angora is a mutation-based fuzzer. The main goal of Angora is to increase branch coverage by solving path constraints without symbolic execution.")
        .arg(Arg::with_name("mode")
             .short("m")
             .long("mode")
             .value_name("Mode")
             .help("Which binary instrumentation framework are you using?")
             .possible_values(&["llvm", "pin"]))
        .arg(Arg::with_name("input_dir")
             .short("i")
             .long("input")
             .value_name("DIR")
             .help("Sets the directory of input seeds, use \"-\" to restart with existing output directory")
             .takes_value(true)
             .required(true))
        .arg(Arg::with_name("output_dir")
             .short("o")
             .long("output")
             .value_name("DIR")
             .help("Sets the directory of outputs")
             .takes_value(true)
             .required(true))
        .arg(Arg::with_name("track_target")
             .short("t")
             .long("track")
             .value_name("TRACK_TARGET")
             .help("Sets the target (USE_TRACK or USE_PIN) for tracking, including taints, cmps.  Only set in LLVM mode.")
             .takes_value(true))
        .arg(Arg::with_name("sanitized_target")
             .short("s")
             .long("san")
             .value_name("SAN_TARGET")
             .help("Sets the target for crash deduplication using ASAN.")
             .takes_value(true).required(true))
        .arg(Arg::with_name("pargs")
            .help("Targeted program (USE_FAST) and arguments. Any \"@@\" will be substituted with the input filename from Angora.")
            .required(true)
            .multiple(true)
            .allow_hyphen_values(true)
            .last(true)
            .index(1))
        .arg(Arg::with_name("memory_limit")
             .short("M")
             .long("memory_limit")
             .value_name("MEM")
             .help("Memory limit for programs, default is 200(MB), set 0 for unlimit memory")
             .takes_value(true))
        .arg(Arg::with_name("time_limit")
             .short("T")
             .long("time_limit")
             .value_name("TIME")
             .help("time limit for programs, default is 1(s), the tracking timeout is 12 * TIME")
             .takes_value(true))
          .arg(Arg::with_name("bind")
          .short("b")
          .long("bind").value_name("BIND").help("\
               Bind Angora to cores starting from the id specified. \
               We assume all cores after the specified core are free. \
               If the cores specified are not enough, we won't bind at all.")
          .takes_value(true))
          .arg(Arg::with_name("thread_jobs")
             .short("j")
             .long("jobs")
             .value_name("JOB")
             .help("Sets the number of thread jobs, default is 1")
             .takes_value(true))
          .arg(Arg::with_name("search_method")
             .short("r")
             .long("search_method")
             .value_name("SearchMethod")
             .help("Which search method to run the program in?")
             .possible_values(&["gd", "random", "mb"]))
          .arg(Arg::with_name("sync_afl")
             .short("S")
             .long("sync_afl")
             .help("Sync the seeds with AFL. Output directory should be in AFL's directory structure."))
          .arg(Arg::with_name("disable_afl")
               .long("disable_afl")
               .help("Disable the fuzzer to mutate inputs using AFL's mutation strategies(Default: false)"))
          .arg(Arg::with_name("disable_exploitation")
               .long("disable_exploitation")
             .help("Disable the fuzzer to mutate sensitive bytes to exploit bugs(Default: false)"))
          .arg(Arg::with_name("disable_dyn_sign")
             .long("disable_dyn_sign")
             .help("Use dynamic sign information(Default: false)"))
          .arg(Arg::with_name("enable_rnd_sign")
             .long("enable_rnd_sign")
             .help("Use dynamic sign information, random sign if static/dynamic can't come to a conclusion(Default: false)"))
          .arg(Arg::with_name("disable_dyn_endian")
             .long("disable_dyn_endian")
             .help("Use dynamic endian information(Default: false)"))
          .arg(Arg::with_name("assume_be")
             .long("assume_be")
             .help("Assume all inputs starts with big endian(Default: false)"))
          .arg(Arg::with_name("max_priority")
             .long("max_priority")
             .value_name("MAX_PRIORITY")
             .takes_value(true)
             .help("Run x rounds and quit. (Default: 65536, i.e. no round limit)"))
          .arg(Arg::with_name("belong")
             .long("belong")
             .help("using belong"))
          .arg(Arg::with_name("order")
             .long("order")
             .help("using order"))
          /*
          .arg(Arg::with_name("disable_multi_pt")
             .long("disable_multi_pt")
             .help("Use all init points we can find to help solving.(Default: false)"))
          .arg(Arg::with_name("update_interval")
             .short("u")
             .long("update_interval")
             .value_name("UPDATE_INTEVAL")
             .help("Update UI every x CPU second"))
          */
        .get_matches();

    let mut config = FuzzerConfig::new();
    config
        .set_enable_afl(matches.occurrences_of("disable_afl") == 0)
        .set_enable_exploitation(matches.occurrences_of("disable_exploitation") == 0)
        .set_enable_dyn_sign(matches.occurrences_of("disable_dyn_sign") == 0)
        .set_enable_random_sign(matches.occurrences_of("enable_rnd_sign") != 0)
        .set_enable_dyn_endian(matches.occurrences_of("disable_dyn_endian") == 0)
        .set_assume_be(matches.occurrences_of("assume_be") != 0)
        .set_enable_multi_pt(matches.occurrences_of("disable_multi_pt") == 0)
        .set_max_priority(value_t!(matches, "max_priority", u16).unwrap_or(std::u16::MAX))
        .set_belong(matches.occurrences_of("belong") != 0)
        .set_order(matches.occurrences_of("order") != 0);
    CONFIG.set(config).unwrap();

    fuzz_main(
        matches.value_of("mode").unwrap_or("llvm"),
        matches.value_of("input_dir").unwrap(),
        matches.value_of("output_dir").unwrap(),
        matches.value_of("track_target").unwrap_or("-"),
        matches.value_of("sanitized_target").unwrap_or("-"),
        matches.values_of_lossy("pargs").unwrap(),
        value_t!(matches, "bind", usize).ok(),
        value_t!(matches, "thread_jobs", usize).unwrap_or(1),
        value_t!(matches, "memory_limit", u64).unwrap_or(angora_common::config::MEM_LIMIT),
        value_t!(matches, "time_limit", u64).unwrap_or(angora_common::config::TIME_LIMIT),
        matches.value_of("search_method").unwrap_or("gd"),
        matches.occurrences_of("sync_afl") > 0,
    );
}
