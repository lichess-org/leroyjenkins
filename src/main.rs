#![feature(addr_parse_ascii)]

use std::{
    cmp::max,
    error::Error,
    hash::BuildHasherDefault,
    io::{self, BufRead},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};

use clap::Parser;
use ipset::{types::HashIp, Session};
use log::{debug, error, info};
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

    /// Do not actually actually test or manage ipsets.
    #[arg(long)]
    dry_run: bool,
}

impl Args {
    fn seconds_to_ban(&self, ban_count: u32) -> u32 {
        self.ipset_base_time * ban_count
    }
}

#[derive(Debug, Copy, Clone)]
enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    fn from_ipv4(ipv4: bool) -> IpFamily {
        if ipv4 {
            IpFamily::V4
        } else {
            IpFamily::V6
        }
    }
}

#[derive(Debug)]
struct ByIpFamily<T> {
    ipv4: T,
    ipv6: T,
}

impl<T> ByIpFamily<T> {
    fn try_new_with<F, E>(mut init: F) -> Result<ByIpFamily<T>, E>
    where
        F: FnMut(IpFamily) -> Result<T, E>,
    {
        Ok(ByIpFamily {
            ipv4: init(IpFamily::V4)?,
            ipv6: init(IpFamily::V6)?,
        })
    }

    fn by_family_mut(&mut self, family: IpFamily) -> &mut T {
        match family {
            IpFamily::V4 => &mut self.ipv4,
            IpFamily::V6 => &mut self.ipv6,
        }
    }
}

struct Leroy {
    sessions: ByIpFamily<Session<HashIp>>,

    ban_log_count_cache: Cache<Vec<u8>, u32, BuildHasherDefault<FxHasher>>,
    recidivism_counts: Cache<IpAddr, u32, BuildHasherDefault<FxHasher>>,

    ban_count: u64,
    ip_count: u64,

    ban_count_start: Instant,
    ip_count_start: Instant,

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
                .time_to_live(Duration::from_secs(args.bl_ttl))
                .build_with_hasher(Default::default()),
            recidivism_counts: Cache::builder()
                .initial_capacity(args.cache_max_size as usize / 5)
                .max_capacity(args.cache_max_size)
                .time_to_live(Duration::from_secs(args.ipset_ban_ttl))
                .build_with_hasher(Default::default()),
            ban_count: 0,
            ip_count: 0,
            ban_count_start: Instant::now(),
            ip_count_start: Instant::now(),
            args,
        })
    }

    fn handle_line(&mut self, ip: Vec<u8>) {
        self.ip_count += 1;

        let ban_log_count: u32 = *self.ban_log_count_cache.get(&ip).unwrap_or(&0) + 1;
        if ban_log_count >= self.args.bl_threshold {
            self.ban(&ip, ban_log_count == max(self.args.bl_threshold, 1));
        }
        self.ban_log_count_cache.insert(ip, ban_log_count);

        if self.ip_count_start.elapsed() > Duration::from_secs(self.args.reporting_ip_time_period) {
            info!(
                "Seen {} ips since {:?}",
                self.ip_count,
                self.ip_count_start.elapsed()
            );
            self.ip_count = 0;
            self.ip_count_start = Instant::now();
        }
    }

    fn ban(&mut self, ip: &[u8], recidivist: bool) {
        let ip: IpAddr = match IpAddr::parse_ascii(ip) {
            Ok(ip) => ip,
            Err(err) => {
                error!(
                    "Error parsing IP from {:?}: {}",
                    String::from_utf8_lossy(ip),
                    err
                );
                return;
            }
        };

        self.ban_count += 1;

        let recidivism: u32 =
            *self.recidivism_counts.get(&ip).unwrap_or(&0) + u32::from(recidivist);
        self.recidivism_counts.insert(ip, recidivism);

        let timeout = self.args.seconds_to_ban(recidivism);
        debug!("Banning {ip} for {timeout}s (recidivism: {recidivism})");

        if !self.args.dry_run {
            if let Err(err) = self
                .sessions
                .by_family_mut(IpFamily::from_ipv4(ip.is_ipv4()))
                .add(ip, Some(timeout))
            {
                error!("Unable to add {ip} to set: {err}");
            }
        }

        if self.ban_count_start.elapsed() > Duration::from_secs(self.args.reporting_ban_time_period)
        {
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
