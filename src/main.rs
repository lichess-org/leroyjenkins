extern crate pretty_env_logger;
#[macro_use]
extern crate log;

use clap::Parser;
use ipset::types::HashIp;
use ipset::Session;
use mini_moka::unsync::Cache;
use rustc_hash::FxHasher;
use std::hash::BuildHasherDefault;
use std::io::{self, BufRead, BufReader};
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::time::Duration;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// File that we'll follow
    #[arg(short, long)]
    ban_log: String,

    /// The time we'll keep records around
    #[arg(short, long)]
    time_to_live: u64,

    /// The number of times they show up before we ban them.
    #[arg(short, long)]
    instances_before_ban: u32,

    /// the first ban time in seconds
    #[arg(short, long)]
    first_ban_time: u32,

    /// The name of the ipset for ipv6
    #[arg(short, long)]
    ipv6_set_name: String,

    /// The name of the ipset for ipv4
    #[arg(short, long)]
    ipv4_set_name: String,

    /// The max size of the ipset
    #[arg(short, long, default_value = "10000000")]
    max_set_size: u32,

    /// The number of seconds to accumulate ban counts before reporting and resetting.
    #[arg(short, long, default_value = "600")]
    ban_reporting_time_period: u128,

    /// The number of seconds to accumulate ip counts before reporting and resetting.
    #[arg(short, long, default_value = "600")]
    ip_reporting_time_period: u128,
}

fn time_to_ban(args: &Args, ban_count: u32) -> u32 {
    args.first_ban_time * ban_count
}

fn follow_banlog(args: &Args) -> io::Result<()> {
    let mut ipv4 = Session::<HashIp>::new(args.ipv4_set_name.clone());
    if let Err(e) = ipv4.create(|builder| {
        builder
            .with_ipv6(false)?
            .with_max_elem(args.max_set_size)?
            .build()
    }) {
        error!("Error creating ipv4 set {}: {:?}", &args.ipv4_set_name, e);
    }
    let mut ipv6 = Session::<HashIp>::new(args.ipv6_set_name.clone());
    if let Err(e) = ipv6.create(|builder| {
        builder
            .with_ipv6(true)?
            .with_max_elem(args.max_set_size)?
            .build()
    }) {
        error!("Error creating ipv6 set {}: {:?}", &args.ipv4_set_name, e);
    }
    let mut cmd = Command::new("tail")
        .args(vec!["-F", &args.ban_log.clone()[..]])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdout = cmd.stdout.as_mut().unwrap();
        let mut stdout_reader = BufReader::new(stdout);
        info!("Following {:?}", args.ban_log);

        let mut cache: Cache<_, _, BuildHasherDefault<FxHasher>> = Cache::builder()
            // Max 10,000 elements
            .max_capacity(500_000) // TODO: I made this number up?
            .time_to_live(Duration::from_secs(args.time_to_live))
            .build_with_hasher(Default::default());

        let mut line = String::new();
        let mut ban_count = 0;
        let mut ip_count = 0;

        let mut ban_count_start = Instant::now();
        let mut ip_count_start = Instant::now();
        while stdout_reader.read_line(&mut line)? != 0 {
            ip_count += 1;
            let count: u32 = *cache.get(&line).unwrap_or(&0) + 1;
            cache.insert(line.clone(), count);
            if count + 1 >= args.instances_before_ban {
                match line[..line.len() - 1].parse::<IpAddr>() {
                    Ok(ip) => {
                        ban_count += 1;
                        _ = match ip {
                            IpAddr::V4(_) => ipv4.add(ip, Some(time_to_ban(args, count))),
                            IpAddr::V6(_) => ipv6.add(ip, Some(time_to_ban(args, count))),
                        };
                        if ban_count_start.elapsed().as_millis()
                            > args.ban_reporting_time_period * 1000
                        {
                            info!(
                                "Banned {} ips in the past {:?}",
                                ban_count,
                                ban_count_start.elapsed()
                            );
                            ban_count = 0;
                            ban_count_start = Instant::now();
                        }
                    }
                    Err(e) => error!("Error parsing ip line: {:?}", e),
                }
            }
            if ip_count_start.elapsed().as_millis() > args.ip_reporting_time_period * 1000 {
                info!("Seen {} ips since {:?}", ip_count, ip_count_start.elapsed());
                ip_count = 0;
                ip_count_start = Instant::now();
            }
            line.clear();
        }
    }

    //cmd.wait().unwrap();
    Ok(())
}

fn main() -> io::Result<()> {
    pretty_env_logger::init();
    let args = Args::parse();
    info!("🔨🔨LEEEEEEEERRRRRROOOOOYYYYYYYYYY JJEEEEEENNNNNNNKKKKKKKIIIIIIINNNNNSSSSSSS🔨🔨");
    follow_banlog(&args)?;
    Ok(())
}
