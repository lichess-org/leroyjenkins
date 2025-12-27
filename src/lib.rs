#![feature(addr_parse_ascii)]

mod ip_family;
mod keyed_limiter;
mod nft_session;

use std::{
    error::Error,
    ffi::CString,
    hash::BuildHasherDefault,
    net::IpAddr,
    num::NonZeroU32,
    time::{Duration, Instant},
};

use clap::Parser;
use governor::Quota;
use log::{debug, error, info};
use mini_moka::unsync::Cache;
use nftnl::ProtoFamily;
use rustc_hash::FxHasher;

use crate::{
    ip_family::{ByIpFamily, IpFamily},
    keyed_limiter::KeyedLimiter,
    nft_session::NftSession,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// The budget of events that has to be exceeded before a ban decision.
    /// Replenished over `--bl-period`.
    #[arg(long)]
    pub bl_threshold: u32,

    /// The amount of time before the rate limiter is fully replenished.
    #[arg(long, default_value = "0s", value_parser = parse_duration)]
    pub bl_period: Duration,

    /// Recidivists get banned longer for their subsequent bans.
    /// This reperesents the amount of time we'll keep the history around.
    /// Everytime we :hammer-time: them, it will reset this countdown.
    /// The user must avoid an ipset ban for this long before their
    /// previous bans are forgotten.
    #[arg(long, alias = "ban-ttl", value_parser = parse_duration)]
    pub ipset_ban_ttl: Duration,

    /// The time of the first ban. Each subsequent ban will be increased
    /// linearly by this amount (resulting in `--ipset-base-time` * ban count).
    #[arg(long, alias = "base-time", value_parser = parse_duration)]
    pub ipset_base_time: Duration,

    /// The name of the nftables table. Protocol family must be `inet`.
    #[arg(long, default_value = "leroy")]
    pub table: CString,

    /// The name of the ipset for IPv4 (must be in `--table` with type
    /// `ipv4_addr` and flags exactly `timeout`).
    #[arg(long, alias = "ipv4-set")]
    pub ipset_ipv4_name: String,

    /// The name of the ipset for IPv6 (must be in `--table` with type
    /// `ipv6_addr` and flags exactly `timeout`).
    #[arg(long, alias = "ipv6-set")]
    pub ipset_ipv6_name: String,

    /// The number of seconds to accumulate ban counts before reporting and
    /// resetting.
    #[arg(long, default_value = "10s", value_parser = parse_duration)]
    pub reporting_ban_time_period: Duration,

    /// The number of seconds to accumulate ip counts before reporting and
    /// resetting.
    #[arg(long, default_value = "10s", value_parser = parse_duration)]
    pub reporting_ip_time_period: Duration,

    /// Initial capacity of the rate limiter table and recidivism cache.
    /// Choose a value large enough for a typical DDoS, to avoid gc and memory
    /// allocation when under attack.
    #[arg(long, default_value = "100000")]
    pub cache_initial_capacity: usize,

    /// The maximum number of entries to keep in the recidivism cache.
    #[arg(long, default_value = "500000")]
    pub cache_max_size: u64,
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
    s.parse::<humantime::Duration>().map(Into::into)
}

pub struct Leroy {
    sessions: ByIpFamily<NftSession>,

    ip_rate_limiters: Option<KeyedLimiter<Vec<u8>, BuildHasherDefault<FxHasher>>>,
    ipset_cache: Cache<IpAddr, (), BuildHasherDefault<FxHasher>>,
    recidivism_counts: Cache<IpAddr, u32, BuildHasherDefault<FxHasher>>,

    line_count: u64,
    line_count_start: Instant,

    args: Args,
}

impl Leroy {
    pub fn new(args: Args) -> Result<Leroy, Box<dyn Error>> {
        Ok(Leroy {
            sessions: ByIpFamily::try_new_with::<_, Box<dyn Error>>(|family| {
                let name = match family {
                    IpFamily::V4 => &args.ipset_ipv4_name,
                    IpFamily::V6 => &args.ipset_ipv6_name,
                };
                NftSession::new(args.table.clone(), name.clone(), ProtoFamily::Inet)
            })?,
            ip_rate_limiters: match NonZeroU32::new(args.bl_threshold) {
                Some(bl_threshold) => Some(KeyedLimiter::new(
                    Quota::with_period(args.bl_period)
                        .ok_or_else(|| format!("--bl-period must be non-zero"))?
                        .allow_burst(bl_threshold),
                    args.cache_initial_capacity,
                    BuildHasherDefault::default(),
                )),
                None => None, // ban on sight
            },
            ipset_cache: Cache::builder()
                .initial_capacity(args.cache_initial_capacity)
                .max_capacity(args.cache_max_size)
                .time_to_live(args.ipset_base_time.saturating_sub(Duration::from_secs(1)))
                .build_with_hasher(Default::default()),
            recidivism_counts: Cache::builder()
                .initial_capacity(args.cache_initial_capacity)
                .max_capacity(args.cache_max_size)
                .time_to_live(args.ipset_ban_ttl)
                .build_with_hasher(Default::default()),
            line_count: 0,
            line_count_start: Instant::now(),
            args,
        })
    }

    pub fn handle_line(&mut self, line: &Vec<u8>) {
        self.line_count += 1;

        if self
            .ip_rate_limiters
            .as_mut()
            .map_or(true, |l| l.check_key(line).is_err())
        {
            match IpAddr::parse_ascii(line) {
                Ok(ip) => self.ban(ip),
                Err(err) => error!(
                    "Error parsing IP from {:?}: {}",
                    String::from_utf8_lossy(line),
                    err
                ),
            }
        }

        if self.line_count % 10 == 0
            && self.line_count_start.elapsed() > self.args.reporting_ip_time_period
        {
            info!(
                "Seen {} lines since {:?}s",
                self.line_count,
                self.line_count_start.elapsed().as_secs()
            );
            self.line_count = 0;
            self.line_count_start = Instant::now();
        }
    }

    fn ban(&mut self, ip: IpAddr) {
        if self.ipset_cache.contains_key(&ip) {
            debug!("{ip} already banned");
            return;
        }

        let recidivism: u32 = *self.recidivism_counts.get(&ip).unwrap_or(&0) + 1;
        let timeout = self.args.seconds_to_ban(recidivism);

        let ban_result = self
            .sessions
            .by_family_mut(IpFamily::from_ipv4(ip.is_ipv4()))
            .add(ip, timeout);

        match ban_result {
            Ok(false) => debug!("{ip} already banned, but was no longer cached"),
            Ok(true) => {
                self.ipset_cache.insert(ip, ());
                self.recidivism_counts.insert(ip, recidivism);
            }
            Err(err) => error!("Unable to add {ip} to set: {err}"),
        }
    }
}
