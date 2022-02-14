use angora::cond_stmt::CondId;
use csv::{Reader, Writer, WriterBuilder};
use log::{info, warn};
use parse_int::parse;
use std::{
    cmp::Ordering,
    collections::HashMap,
    env::args,
    error::Error,
    fmt::{self, Debug},
    fs::File,
    path::Path,
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Status {
    Solved = 0,
    Unsolved = 1,
    Undiscover = 2,
}
impl Debug for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Self::Solved => write!(f, "S"),
            Self::Unsolved => write!(f, "U"),
            Self::Undiscover => write!(f, "X"),
        }
    }
}

fn parse_csv<P: AsRef<Path>>(path: P) -> Result<HashMap<CondId, Status>, Box<dyn Error>> {
    let mut reader = Reader::from_path(path)?;
    let mut map = HashMap::new();
    for result in reader.records() {
        let line = result?;
        let cmpid = parse::<u32>(&line[0])?;
        let context = parse::<u32>(&line[1])?;
        let order = parse::<u32>(&line[2])?;
        let op = parse::<u32>(&line[5])?;
        let status = if &line[4] == " true" {
            Status::Solved
        } else {
            Status::Unsolved
        };
        let id = CondId::new(cmpid, context, order, op);
        map.insert(id, status);
    }
    Ok(map)
}

fn merge_csv(merge: &mut HashMap<CondId, Vec<Status>>, new: HashMap<CondId, Status>, len: usize) {
    new.iter().for_each(|(cond, status)| {
        merge
            .entry(*cond)
            .or_insert(
                // This cond is not in global.
                vec![Status::Undiscover; len],
            )
            .push(*status);
    });
    // This cond is not in local.
    merge.iter_mut().for_each(|(cond, status)| {
        if new.get(cond).is_none() {
            status.push(Status::Undiscover);
        }
    });
}

fn get_output_writer() -> Result<Writer<File>, Box<dyn Error>> {
    let mut path = Path::new("merge.csv");
    let mut idx = 0;
    let mut name;
    loop {
        if !path.exists() {
            break;
        }
        warn!("Output file: {:?} already exists", path);
        idx += 1;
        name = format!("merge.{}.csv", idx);
        path = Path::new(&name);
    }
    Ok(WriterBuilder::new().from_path(path)?)
}

fn main() -> Result<(), Box<dyn Error>> {
    pretty_env_logger::init();

    let mut writer = get_output_writer()?;
    let mut header: Vec<String> = vec!["cmpid", "context", "order", "op"]
        .into_iter()
        .map(|s| String::from(s))
        .collect();

    let mut merge = HashMap::new();
    let mut len = 0;
    for arg in args().skip(1) {
        if !arg.ends_with(".csv") {
            warn!("{:?} is not a csv file, skip", arg);
            continue;
        }
        let path = Path::new(&arg);
        if !path.exists() {
            warn!("{:?} does not exist, skip", path);
            continue;
        }
        info!("Parsing {:?}", path);
        header.push(String::from(arg.clone()));
        let new = parse_csv(path)?;
        merge_csv(&mut merge, new, len);
        len += 1;
    }
    if merge.is_empty() {
        warn!("No csv parsed, nothing to merge.");
        return Ok(());
    }
    writer.write_record(header)?;

    let mut merge: Vec<(CondId, Vec<Status>)> = merge.into_iter().collect();
    merge.sort_by(|(id_a, status_a), (id_b, status_b)| {
        assert!(status_a.len() == status_b.len());
        for i in 0..status_a.len() {
            if status_a[i] != status_b[i] {
                return status_a[i].cmp(&status_b[i]);
            }
        }
        if id_a != id_b {
            return id_a.cmp(id_b);
        }
        Ordering::Equal
    });

    let vec: Vec<Vec<String>> = merge
        .iter()
        .map(|(id, status)| {
            let mut vec = vec![
                format!("0x{:08x}", id.cmpid),
                format!("{}", id.context),
                format!("{}", id.order),
                format!("0x{:x}", id.op),
            ];
            let s: Vec<String> = status.iter().map(|s| format!("{:?}", s)).collect();
            vec.extend(s);
            vec
        })
        .collect();

    for r in vec.into_iter() {
        writer.write_record(r)?;
    }
    Ok(())
}
