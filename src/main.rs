#![feature(addr_parse_ascii)]

mod ip_family;

use std::{
    error::Error,
    hash::BuildHasherDefault,
    io::{self, BufRead},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
    time::{Duration, Instant},
};

use clap::Parser;
use governor::{clock::QuantaInstant, DefaultDirectRateLimiter, NotUntil, Quota, RateLimiter};
use ipset::{types::HashIp, Session};
use log::{debug, error, info};
use mini_moka::unsync::Cache;
use rustc_hash::FxHasher;

use crate::ip_family::{ByIpFamily, IpFamily};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The number of events we will see before a ban decision, combines with
    /// `bl_period` to determine the exact rate limit.
    /// see: https://github.com/antifuchs/governor/blob/master/governor/src/quota.rs#L9
    #[arg(long)]
    bl_threshold: NonZeroU32,

    /// The amount of time before the rate limiter is fully replenished.
    /// Uses humantime to parse the duration.
    /// See: https://docs.rs/humantime/latest/humantime/ for details
    ///
    /// Combines with `bl_threshold` to determine the exact rate limit
    /// see: https://github.com/antifuchs/governor/blob/master/governor/src/quota.rs#L9
    #[arg(long, value_parser = parse_duration)]
    bl_period: Duration,

    /// Recidivists get banned longer for their subsequent bans.
    /// This reperesents the amount of time we'll keep the history around.
    /// Everytime we :hammer-time: them, it will reset this countdown.
    /// The user must avoid an ipset ban for this long before their
    /// previous ipset bans are forgotten.
    ///
    /// Uses humantime to parse the duration.
    /// See: https://docs.rs/humantime/latest/humantime/ for details
    #[arg(long, value_parser = parse_duration)]
    ipset_ban_ttl: Duration,

    /// The time of the first ban. Each subsequent ban will be increased
    /// linearly by this amount (resulting in --ipset-base-time * ban count).
    ///
    /// Uses humantime to parse the duration.
    /// See: https://docs.rs/humantime/latest/humantime/ for details
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
    ///
    /// Uses humantime to parse the duration.
    /// See: https://docs.rs/humantime/latest/humantime/ for details
    #[arg(long, default_value = "10s", value_parser = parse_duration)]
    reporting_ban_time_period: Duration,

    /// The number of seconds to accumulate ip counts before reporting and
    /// resetting.
    ///
    /// Uses humantime to parse the duration.
    /// See: https://docs.rs/humantime/latest/humantime/ for details
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

fn parse_duration(s: &str) -> Result<Duration, humantime::DurationError> {
    s.parse::<humantime::Duration>().map(|hd| hd.into())
}

struct Leroy {
    sessions: ByIpFamily<Session<HashIp>>,

    ip_rate_limiters: Cache<Vec<u8>, DefaultDirectRateLimiter, BuildHasherDefault<FxHasher>>,
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
            ip_rate_limiters: Cache::builder()
                .initial_capacity(args.cache_max_size as usize / 5)
                .max_capacity(args.cache_max_size)
                // TODO: is 2s + the bl_period enough time? I think so.
                .time_to_live(Duration::from_secs(2) + args.bl_period)
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

        match self.ip_rate_limiters.get(&line) {
            Some(rate_limiter) => {
                let check_result = rate_limiter.check();
                self.handle_check_result(&line, check_result);
            }
            None => {
                let rate_limiter = RateLimiter::direct(
                    Quota::with_period(self.args.bl_period)
                        .expect("Rate limits MUST Be non-zero")
                        .allow_burst(self.args.bl_threshold),
                );
                self.handle_check_result(&line, rate_limiter.check());
                self.ip_rate_limiters.insert(line, rate_limiter);
            }
        };

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

    fn handle_check_result(
        &mut self,
        line: &[u8],
        check_result: Result<(), NotUntil<QuantaInstant>>,
    ) {
        if check_result.is_err() {
            match IpAddr::parse_ascii(&line) {
                Ok(ip) => self.ban(ip),
                Err(err) => error!(
                    "Error parsing IP from {:?}: {}",
                    String::from_utf8_lossy(&line),
                    err
                ),
            }
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
