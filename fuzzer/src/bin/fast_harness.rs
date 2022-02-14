use angora;
use angora_common::*;
use clap::*;
use std::{collections::HashMap, io, process::Command, sync::Arc};

struct FastHarness {
    pub branches: angora::branches::Branches,
    pub t_conds: angora::cond_stmt::ShmConds,
    // envs: HashMap<String, String>,
    forksrv: angora::executor::forksrv::Forksrv,
}

impl FastHarness {
    pub fn new(pargs: Vec<String>) -> Self {
        let shm_id = format!(
            "{:?}-{:?}-shm",
            std::process::id(),
            std::thread::current().id()
        );
        let global_branches = Arc::new(angora::branches::GlobalBranches::new());
        let mut branches = angora::branches::Branches::new(global_branches, &shm_id);
        let t_conds = angora::cond_stmt::ShmConds::new();

        let mut envs = HashMap::new();
        envs.insert(
            defs::ASAN_OPTIONS_VAR.to_string(),
            defs::ASAN_OPTIONS_CONTENT.to_string(),
        );
        envs.insert(
            defs::MSAN_OPTIONS_VAR.to_string(),
            defs::MSAN_OPTIONS_CONTENT.to_string(),
        );
        envs.insert(
            angora_common::defs::BRANCHES_SHM_ENV_VAR.to_string(),
            shm_id,
        );
        envs.insert(
            defs::COND_STMT_ENV_VAR.to_string(),
            t_conds.get_id().to_string(),
        );
        let clang_lib = Command::new("llvm-config")
            .arg("--libdir")
            .output()
            .expect("Can't find llvm-config")
            .stdout;
        let clang_lib = String::from_utf8(clang_lib).unwrap();
        let ld_library = "$LD_LIBRARY_PATH:".to_string() + clang_lib.trim();
        envs.insert(defs::LD_LIBRARY_PATH_VAR.to_string(), ld_library.clone());

        let fd = angora::executor::pipe_fd::PipeFd::new("/tmp/test_input");
        // Remove the socket file if it is already there, or the forkserver fails
        let _ = std::fs::remove_file("/tmp/test_socket");
        let fast_bin: String = pargs[0].clone();
        let mut args = Vec::new();
        let mut is_stdin = true;
        for i in 1..pargs.len() {
            if pargs[i] == "@@" {
                args.push("/tmp/test_socket".to_string());
                is_stdin = false;
            } else {
                args.push(pargs[i].clone());
            }
        }
        let forksrv = angora::executor::forksrv::Forksrv::new(
            "/tmp/test_socket",
            &(fast_bin, args),
            &envs,
            fd.as_raw_fd(),
            is_stdin,
            false,
            angora_common::config::TIME_LIMIT,
            angora_common::config::MEM_LIMIT,
        );

        branches.resize();

        Self {
            branches,
            t_conds,
            // envs,
            forksrv,
        }
    }

    pub fn run_target(&mut self) {
        self.branches.clear_trace();
        self.forksrv.run();
    }
}

fn main() {
    let app = App::new("fast_harness")
        .arg(
            Arg::with_name("function id")
                .short("f")
                .long("fnid")
                .takes_value(true)
                .value_name("FN_ID")
                .required_unless("interactive"),
        )
        .arg(
            Arg::with_name("condition id")
                .short("c")
                .long("cond_id")
                .takes_value(true)
                .value_name("COND_ID")
                .required_unless("interactive"),
        )
        .arg(
            Arg::with_name("condition type")
                .short("t")
                .long("cond_type")
                .takes_value(true)
                .value_name("COND_TYPE")
                .required_unless("interactive"),
        )
        .arg(Arg::with_name("pargs")
            .help("Targeted program (USE_FAST) and arguments. Any \"@@\" will be substituted with the input filename from Angora.")
            .required(true)
            .multiple(true)
            .allow_hyphen_values(true)
            .last(true)
            .index(1))
        .arg(
            Arg::with_name("interactive")
                .short("i")
                .long("interactive")
                .takes_value(false)
                .conflicts_with_all(&["condition id", "condition type", "function id"])
                .required_unless_one(&["condition id", "condition type", "function id"]),
        );
    let matches = app.get_matches();
    let stdin = io::stdin();
    let pargs = matches.values_of_lossy("pargs").unwrap();
    let mut harness = FastHarness::new(pargs);
    if matches.is_present("interactive") {
        // interactive mode
        println!("Interactive mode.\nEnter the following information.");
        let prompts = ["Condition ID: ", "Function ID: ", "Condition Type: "];
        let mut vals = vec![0_u32; prompts.len()];
        let mut i = 0;
        loop {
            let mut line = String::new();
            if i >= prompts.len() {
                break;
            }
            println!("{}", &prompts[i]);
            if let Ok(read_bytes) = stdin.read_line(&mut line) {
                if read_bytes < 1 {
                    continue;
                }
                if let Ok(val) = line.trim().parse::<u32>() {
                    vals[i] = val;
                    i += 1;
                }
            } else {
                break;
            }
        }
        if i < prompts.len() {
            println!("Incomplete information. Exiting.");
            std::process::exit(1);
        } else {
            harness.t_conds.cond.cmpid = vals[0];
            //harness.t_conds.cond.fn_id = vals[1];
            harness.t_conds.cond.op = vals[2];
        }
    } else {
        let cond_id = matches
            .value_of("condition id")
            .unwrap_or_default()
            .parse::<u32>()
            .unwrap();
        let cond_type = matches
            .value_of("condition type")
            .unwrap_or_default()
            .parse::<u32>()
            .unwrap();
        /*
        let fn_id = matches
            .value_of("function id")
            .unwrap_or_default()
            .parse::<u32>()
            .unwrap();
        */
        harness.t_conds.cond.cmpid = cond_id;
        //harness.t_conds.cond.fn_id = fn_id;
        harness.t_conds.cond.op = cond_type;
    }

    let mut line = String::new();
    println!("Press ENTER to execute the target binary.");
    if let Ok(_) = stdin.read_line(&mut line) {
        harness.run_target();
        println!(
            "Branches: {:?}\nCondition: {:?}",
            &harness.branches, &harness.t_conds
        );
    } else {
    }
}
