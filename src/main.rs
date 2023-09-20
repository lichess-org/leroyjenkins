use std::{
    hash::BuildHasherDefault,
    io::{self, BufRead},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::exit,
    time::{Duration, Instant},
};

use clap::Parser;
use ipset::{types::HashIp, Session};
use log::{error, info};
use mini_moka::unsync::Cache;
use rustc_hash::FxHasher;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The time we'll keep the ban_log buckets around.
    /// the user must avoid an nginx ban for this long before their
    /// previous nginx bans are forgotten. Note, the first ban should probably
    /// be long enough that this will expire during its duration
    #[arg(long)]
    bl_ttl: u64,

    /// The number of times they can show up in the ban log before hammer-time
    #[arg(long)]
    bl_threshold: u32,

    /// Recidivists get banned for longer for their subsequent bans,
    /// this reperesents the amount of time we'll keep this history around.
    /// Everytime we :hammer-time: them, it will reset this countdown
    /// the user must avoid an ipset ban for this long before their
    /// previous ipset bans are forgotten.
    #[arg(long)]
    ipset_ban_ttl: u64,

    /// (In seconds): The time of the first ban. Each subsequent ban will be increased
    /// linearly by this amount (ban_count * base_time)
    #[arg(long)]
    ipset_base_time: u32,

    /// The name of the ipset for ipv4
    #[arg(long)]
    ipset_ipv4_name: String,

    /// The name of the ipset for ipv6
    #[arg(long)]
    ipset_ipv6_name: String,

    /// The max size of both ipsets.
    #[arg(long, default_value = "10000000")]
    ipset_max_size: u32,

    /// The number of seconds to accumulate ban counts before reporting and resetting.
    #[arg(long, default_value = "10")]
    reporting_ban_time_period: u64,

    /// The number of seconds to accumulate ip counts before reporting and resetting.
    #[arg(long, default_value = "10")]
    reporting_ip_time_period: u64,

    /// The number of elements to keep in the cache that we use, larger is more memory
    /// smaller is probably slightly faster, but maybe not.
    #[arg(long, default_value = "500000")]
    cache_max_size: u64,
}

fn time_to_ban(args: &Args, ban_count: u32) -> u32 {
    args.ipset_base_time * ban_count
}

fn log_and_ignore_err<T, E: std::fmt::Debug>(prefix: &'static str, res: Result<T, E>) {
    if let Err(e) = res {
        error!("{}: {:?}", prefix, e);
    }
}

fn follow_banlog(args: &Args) -> io::Result<()> {
    let mut ipv4 = Session::<HashIp>::new(args.ipset_ipv4_name.clone());
    if let Err(err) = ipv4.test(IpAddr::V4(Ipv4Addr::LOCALHOST)) {
        error!("failed to test ipv4 set: {err:?}. please create before running.");
        //exit(-1);
    }

    let mut ipv6 = Session::<HashIp>::new(args.ipset_ipv6_name.clone());
    if let Err(err) = ipv6.test(IpAddr::V6(Ipv6Addr::LOCALHOST)) {
        error!("failed to test ipv6 set: {err:?}. please create before running.");
        //exit(-1);
    }

    let mut ban_log_count_cache: Cache<_, _, BuildHasherDefault<FxHasher>> = Cache::builder()
        .max_capacity(args.cache_max_size)
        .time_to_live(Duration::from_secs(args.bl_ttl))
        .build_with_hasher(Default::default());

    let mut ipset_ban_count_cache: Cache<_, _, BuildHasherDefault<FxHasher>> = Cache::builder()
        .max_capacity(args.cache_max_size)
        .time_to_live(Duration::from_secs(args.ipset_ban_ttl))
        .build_with_hasher(Default::default());

    let mut ban_count = 0;
    let mut ip_count = 0;

    let mut ban_count_start = Instant::now();
    let mut ip_count_start = Instant::now();

    let mut stdin = io::stdin().lock();
    let mut line = String::new();
    while stdin.read_line(&mut line)? != 0 {
        ip_count += 1;
        let ban_log_count: u32 = *ban_log_count_cache.get(&line).unwrap_or(&0) + 1;
        ban_log_count_cache.insert(line.clone(), ban_log_count);
        if ban_log_count + 1 >= args.bl_threshold {
            let ipset_ban_count: u32 = *ipset_ban_count_cache.get(&line).unwrap_or(&0) + 1;
            match line[..line.len() - 1].parse::<IpAddr>() {
                Ok(ip) => {
                    ban_count += 1;
                    match ip {
                        IpAddr::V4(_) => {
                            log_and_ignore_err(
                                "Unable to add to ipv4 set",
                                ipv4.add(ip, Some(time_to_ban(args, ipset_ban_count))),
                            );
                        }
                        IpAddr::V6(_) => {
                            log_and_ignore_err(
                                "Unable to add to ipv6 set",
                                ipv6.add(ip, Some(time_to_ban(args, ipset_ban_count))),
                            );
                        }
                    };
                    if ban_count_start.elapsed()
                        > Duration::from_secs(args.reporting_ban_time_period)
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
        if ip_count_start.elapsed() > Duration::from_secs(args.reporting_ip_time_period) {
            info!("Seen {} ips since {:?}", ip_count, ip_count_start.elapsed());
            ip_count = 0;
            ip_count_start = Instant::now();
        }
        line.clear();
    }

    Ok(())
}

fn main() -> io::Result<()> {
    pretty_env_logger::init();
    let args = Args::parse();
    info!(
        "🔨🪓🪖🥚LEEEEEEEERRRRRROOOOOYYYYYYYYYY JJEEEEEENNNNNNNKKKKKKKIIIIIIINNNNNSSSSSSS🥚🪖🪓🔨"
    );
    info!("{:?}", args);
    follow_banlog(&args)
}
