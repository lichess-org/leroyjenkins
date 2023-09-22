#![feature(addr_parse_ascii)]

mod ip_family;

use std::{
    error::Error,
    hash::BuildHasherDefault,
    io::{self, BufRead},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::ParseIntError,
    time::{Duration, Instant},
};

use clap::Parser;
use ipset::{types::HashIp, Session};
use log::{debug, error, info};
use mini_moka::unsync::Cache;
use rustc_hash::FxHasher;

use crate::ip_family::{ByIpFamily, IpFamily};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The time we'll keep the nginx log buckets around.
    /// The user must avoid an nginx log for this long before their
    /// previous nginx bans are forgotten. Note, the first ban should probably
    /// be long enough that this will expire during its duration.
    #[arg(long, value_parser = parse_duration)]
    bl_ttl: Duration,

    /// The number of times they can show up in the ban log before hammer-time.
    #[arg(long)]
    bl_threshold: u32,

    /// Recidivists get banned longer for their subsequent bans.
    /// This reperesents the amount of time we'll keep the history around.
    /// Everytime we :hammer-time: them, it will reset this countdown.
    /// The user must avoid an ipset ban for this long before their
    /// previous ipset bans are forgotten.
    #[arg(long, value_parser = parse_duration)]
    ipset_ban_ttl: Duration,

    /// The time of the first ban. Each subsequent ban will be increased
    /// linearly by this amount (resulting in --ipset-base-time * ban count).
    #[arg(long, value_parser = parse_duration)]
    ipset_base_time: Duration,

    /// The name of the ipset for IPv4.
    #[arg(long)]
    ipset_ipv4_name: String,

    /// The name of the ipset for IPv6.
    #[arg(long)]
    ipset_ipv6_name: String,

    /// The number of seconds to accumulate ban counts before reporting and
    /// resetting.
    #[arg(long, default_value = "10s", value_parser = parse_duration)]
    reporting_ban_time_period: Duration,

    /// The number of seconds to accumulate ip counts before reporting and
    /// resetting.
    #[arg(long, default_value = "10s", value_parser = parse_duration)]
    reporting_ip_time_period: Duration,

    /// The number of elements to keep in the cache that we use, larger is more
    /// memory smaller is probably slightly faster, but maybe not.
    #[arg(long, default_value = "500000")]
    cache_max_size: u64,

    /// Do not actually actually test or manage ipsets. Useful for test runs
    /// without privileges.
    #[arg(long)]
    dry_run: bool,
}

impl Args {
    fn seconds_to_ban(&self, ban_count: u32) -> u32 {
        self.ipset_base_time
            .checked_mul(ban_count)
            .and_then(|time| u32::try_from(time.as_secs()).ok())
            .unwrap_or(u32::MAX)
    }
}

fn parse_duration(s: &str) -> Result<Duration, ParseIntError> {
    let (s, factor) = if let Some(s) = s.strip_suffix('d') {
        (s, 60 * 60 * 24)
    } else if let Some(s) = s.strip_suffix('h') {
        (s, 60 * 60)
    } else if let Some(s) = s.strip_suffix('m') {
        (s, 60)
    } else {
        (s.strip_suffix('s').unwrap_or(s), 1)
    };

    Ok(Duration::from_secs(
        u64::from(s.trim().parse::<u32>()?) * factor,
    ))
}

struct Leroy {
    sessions: ByIpFamily<Session<HashIp>>,

    ban_log_count_cache: Cache<Vec<u8>, u32, BuildHasherDefault<FxHasher>>,
    recidivism_counts: Cache<IpAddr, u32, BuildHasherDefault<FxHasher>>,

    line_count: u64,
    line_count_start: Instant,

    ban_count: u64,
    ban_count_start: Instant,

    args: Args,
}

impl Leroy {
    fn new(args: Args) -> Result<Leroy, Box<dyn Error>> {
        Ok(Leroy {
            sessions: ByIpFamily::try_new_with::<_, Box<dyn Error>>(|family| {
                let (name, localhost) = match family {
                    IpFamily::V4 => (&args.ipset_ipv4_name, IpAddr::V4(Ipv4Addr::LOCALHOST)),
                    IpFamily::V6 => (&args.ipset_ipv6_name, IpAddr::V6(Ipv6Addr::LOCALHOST)),
                };
                let mut session = Session::<HashIp>::new(name.clone());
                if !args.dry_run {
                    session.test(localhost).map_err(|err| {
                        format!("Failed to test set {name:?}: {err}. Please create before running.")
                    })?;
                }
                Ok(session)
            })?,
            ban_log_count_cache: Cache::builder()
                .initial_capacity(args.cache_max_size as usize / 5)
                .max_capacity(args.cache_max_size)
                .time_to_live(args.bl_ttl)
                .build_with_hasher(Default::default()),
            recidivism_counts: Cache::builder()
                .initial_capacity(args.cache_max_size as usize / 5)
                .max_capacity(args.cache_max_size)
                .time_to_live(args.ipset_ban_ttl)
                .build_with_hasher(Default::default()),
            line_count: 0,
            ban_count: 0,
            line_count_start: Instant::now(),
            ban_count_start: Instant::now(),
            args,
        })
    }

    fn handle_line(&mut self, line: Vec<u8>) {
        self.line_count += 1;

        let ban_log_count: u32 = *self.ban_log_count_cache.get(&line).unwrap_or(&0) + 1;
        if ban_log_count >= self.args.bl_threshold {
            match IpAddr::parse_ascii(&line) {
                Ok(ip) => self.ban(ip),
                Err(err) => error!(
                    "Error parsing IP from {:?}: {}",
                    String::from_utf8_lossy(&line),
                    err
                ),
            }
        }
        self.ban_log_count_cache.insert(line, ban_log_count);

        if self.line_count_start.elapsed() > self.args.reporting_ip_time_period {
            info!(
                "Seen {} lines since {:?}",
                self.line_count,
                self.line_count_start.elapsed()
            );
            self.line_count = 0;
            self.line_count_start = Instant::now();
        }
    }

    fn ban(&mut self, ip: IpAddr) {
        let recidivism: u32 = *self.recidivism_counts.get(&ip).unwrap_or(&0) + 1;
        let timeout = self.args.seconds_to_ban(recidivism);

        let ban_result = if self.args.dry_run {
            Ok(true)
        } else {
            self.sessions
                .by_family_mut(IpFamily::from_ipv4(ip.is_ipv4()))
                .add(ip, Some(timeout))
        };

        match ban_result {
            Ok(false) => debug!("{ip} already banned"),
            Ok(true) => {
                debug!("Banned {ip} for {timeout}s (recidivism: {recidivism})");
                self.ban_count += 1;
                self.recidivism_counts.insert(ip, recidivism);
            }
            Err(err) => error!("Unable to add {ip} to set: {err}"),
        }

        if self.ban_count_start.elapsed() > self.args.reporting_ban_time_period {
            info!(
                "Banned {} ips in the past {:?}",
                self.ban_count,
                self.ban_count_start.elapsed()
            );
            self.ban_count = 0;
            self.ban_count_start = Instant::now();
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    pretty_env_logger::init();

    let args = Args::parse();
    info!(
        "🔨🪓🪖🥚LEEEEEEEERRRRRROOOOOYYYYYYYYYY JJEEEEEENNNNNNNKKKKKKKIIIIIIINNNNNSSSSSSS🥚🪖🪓🔨"
    );
    info!("{:?}", args);

    let mut leroy = Leroy::new(args)?;
    for line in io::stdin().lock().split(b'\n') {
        leroy.handle_line(line?);
    }

    Ok(())
}
