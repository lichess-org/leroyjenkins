#![feature(addr_parse_ascii)]
#![feature(ip_as_octets)]

mod keyed_limiter;
mod nftnl;

use std::{
    error::Error,
    ffi::CString,
    hash::BuildHasherDefault,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
    time::{Duration, Instant},
};

use clap::Parser;
use governor::Quota;
use libc::{
    NFPROTO_INET, NFT_MSG_DELSETELEM, NFT_MSG_NEWSETELEM, NLM_F_ACK, NLM_F_CREATE, NLM_F_REQUEST,
};
use log::{debug, error, info};
use mini_moka::unsync::Cache;
use mnl_sys::MNL_SOCKET_BUFFER_SIZE;
use rustc_hash::FxHasher;

use crate::{
    keyed_limiter::KeyedLimiter,
    nftnl::{NftnlSet, NftnlSetElem, NlmsgBatch, Seq},
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
    #[arg(long, alias = "ipv4-set", default_value = "leroy4")]
    pub ipset_ipv4_name: CString,

    /// The name of the ipset for IPv6 (must be in `--table` with type
    /// `ipv6_addr` and flags exactly `timeout`).
    #[arg(long, alias = "ipv6-set", default_value = "leroy6")]
    pub ipset_ipv6_name: CString,

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

    /// Do not actually communicate with the kernel. Useful for testing without
    /// privileges.
    #[arg(long)]
    pub dry_run: bool,
}

impl Args {
    fn time_to_ban(&self, ban_count: u32) -> Duration {
        self.ipset_base_time
            .checked_mul(ban_count)
            .unwrap_or(Duration::MAX)
    }
}

fn parse_duration(s: &str) -> Result<Duration, humantime::DurationError> {
    s.parse::<humantime::Duration>().map(Into::into)
}

pub struct Leroy {
    socket: Option<mnl::Socket>,
    nlmsg_batch: NlmsgBatch,
    nlmsg_recv_buffer: Vec<u8>,

    ip_rate_limiters: Option<KeyedLimiter<Vec<u8>, BuildHasherDefault<FxHasher>>>,
    ipset_cache: Cache<IpAddr, (), BuildHasherDefault<FxHasher>>,
    recidivism_counts: Cache<IpAddr, u32, BuildHasherDefault<FxHasher>>,

    line_count: u64,
    line_count_start: Instant,

    args: Args,
}

impl Leroy {
    pub fn new(args: Args) -> Result<Leroy, Box<dyn Error>> {
        let mut leroy = Leroy {
            socket: (!args.dry_run)
                .then(|| mnl::Socket::new(mnl::Bus::Netfilter))
                .transpose()?,
            nlmsg_batch: NlmsgBatch::new(Seq(0)),
            nlmsg_recv_buffer: vec![0; MNL_SOCKET_BUFFER_SIZE() as usize],
            ip_rate_limiters: match NonZeroU32::new(args.bl_threshold) {
                Some(bl_threshold) => Some(KeyedLimiter::new(
                    Quota::with_period(args.bl_period)
                        .ok_or_else(|| "--bl-period must be non-zero".to_owned())?
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
        };

        // Ban some reserved IPs to test configuration and kernel communication.
        leroy.ban(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))?;
        leroy.ban(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))?;

        Ok(leroy)
    }

    pub fn handle_line(&mut self, line: &Vec<u8>) {
        self.line_count += 1;

        if self
            .ip_rate_limiters
            .as_mut()
            .is_none_or(|l| l.check_key(line).is_err())
        {
            match IpAddr::parse_ascii(line) {
                Ok(ip) => self.ban(ip).expect("ban"), // Error likely unrecoverable
                Err(err) => error!(
                    "Error parsing IP from {:?}: {}",
                    String::from_utf8_lossy(line),
                    err
                ),
            }
        }

        if self.line_count.is_multiple_of(10)
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

    fn ban(&mut self, ip: IpAddr) -> io::Result<()> {
        if self.ipset_cache.contains_key(&ip) {
            debug!("{ip} already banned");
            return Ok(());
        }

        let recidivism: u32 = *self.recidivism_counts.get(&ip).unwrap_or(&0) + 1;
        let timeout = self.args.time_to_ban(recidivism);

        let mut set = NftnlSet::new();
        set.set_table(&self.args.table);
        set.set_name(match ip {
            IpAddr::V4(_) => &self.args.ipset_ipv4_name,
            IpAddr::V6(_) => &self.args.ipset_ipv6_name,
        });

        let mut elem = NftnlSetElem::new();
        elem.set_key(ip);
        elem.set_timeout(timeout);
        set.add(elem);

        self.nlmsg_batch.reset();
        self.nlmsg_batch.begin();
        // Ensure following delete succeeds unconditionally.
        self.nlmsg_batch.set_elems(
            NFT_MSG_NEWSETELEM as u16,
            NFPROTO_INET as u16,
            (NLM_F_CREATE | NLM_F_REQUEST) as u16,
            &set,
        );
        // Delete to reset timeout if element already exists.
        self.nlmsg_batch.set_elems(
            NFT_MSG_DELSETELEM as u16,
            NFPROTO_INET as u16,
            (NLM_F_CREATE | NLM_F_REQUEST) as u16,
            &set,
        );
        // Add element with new timeout.
        self.nlmsg_batch.set_elems(
            NFT_MSG_NEWSETELEM as u16,
            NFPROTO_INET as u16,
            (NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK) as u16,
            &set,
        );
        let seq = self.nlmsg_batch.seq();
        self.nlmsg_batch.end();

        if let Some(socket) = &mut self.socket {
            let bytes = self.nlmsg_batch.as_bytes();
            let tx = socket.send(bytes)?;
            if tx != bytes.len() {
                return Err(io::Error::other("did not send entire batch"));
            }

            for response in socket.recv(&mut self.nlmsg_recv_buffer[..])? {
                let response = response?;
                mnl::cb_run(response, seq.0, socket.portid())?;
            }
        }

        self.ipset_cache.insert(ip, ());
        self.recidivism_counts.insert(ip, recidivism);

        Ok(())
    }
}
