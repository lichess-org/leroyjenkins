#![feature(addr_parse_ascii)]
#![feature(ip_as_octets)]

mod keyed_limiter;
mod mnl;
mod nftnl;
mod seq;

use std::{
    error::Error,
    ffi::CString,
    hash::BuildHasherDefault,
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
    time::{Duration, Instant},
};

use clap::Parser;
use governor::Quota;
use libc::{
    NFPROTO_INET, NFT_MSG_DELSETELEM, NFT_MSG_NEWSETELEM, NLM_F_ACK, NLM_F_CREATE, NLM_F_REQUEST,
};
use log::{debug, error, info, warn};
use mini_moka::unsync::Cache;
use mnl_sys::MNL_SOCKET_BUFFER_SIZE;
use rustc_hash::FxHasher;
use seq::SeqGenerator;

use crate::{
    keyed_limiter::KeyedLimiter,
    mnl::{MnlReceiveBuffer, MnlSocket},
    nftnl::{NftnlSet, NftnlSetElem, NlmsgBatch},
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
    #[arg(long, alias = "ipset-ban-ttl", value_parser = parse_duration)]
    pub ban_ttl: Duration,

    /// The time of the first ban. Each subsequent ban will be increased
    /// linearly by this amount (resulting in `--ipset-base-time` * ban count).
    #[arg(long, alias = "ipset-base-time", value_parser = parse_duration)]
    pub ban_base_time: Duration,

    /// The name of the nftables table. Protocol family must be `inet`.
    #[arg(long, default_value = "leroy")]
    pub table: CString,

    /// The name of the ipset for IPv4 (must be in `--table` with type
    /// `ipv4_addr` and flags exactly `timeout`).
    #[arg(long, alias = "ipset-ipv4-name", default_value = "leroy4")]
    pub ipv4_set: CString,

    /// The name of the ipset for IPv6 (must be in `--table` with type
    /// `ipv6_addr` and flags exactly `timeout`).
    #[arg(long, alias = "ipset-ipv6-name", default_value = "leroy6")]
    pub ipv6_set: CString,

    #[arg(long, alias = "reporting-ban-time-period", default_value = "1m", value_parser = parse_duration)]
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
        self.ban_base_time
            .checked_mul(ban_count)
            .unwrap_or(Duration::MAX)
    }
}

fn parse_duration(s: &str) -> Result<Duration, humantime::DurationError> {
    s.parse::<humantime::Duration>().map(Into::into)
}

pub struct Leroy {
    socket: Option<MnlSocket>,
    seq_generator: SeqGenerator,
    nlmsg_batch: NlmsgBatch,
    nlmsg_recv_buffer: MnlReceiveBuffer,

    ip_rate_limiters: Option<KeyedLimiter<Vec<u8>, BuildHasherDefault<FxHasher>>>,
    ban_cache: Cache<IpAddr, (), BuildHasherDefault<FxHasher>>,
    recidivism_counts: Cache<IpAddr, u32, BuildHasherDefault<FxHasher>>,

    line_count: u64,
    line_count_start: Instant,

    ban_count: u64,
    ban_count_start: Instant,

    args: Args,
}

impl Leroy {
    pub fn new(args: Args) -> Result<Leroy, Box<dyn Error>> {
        let mut leroy = Leroy {
            socket: (!args.dry_run).then(MnlSocket::new_netfilter).transpose()?,
            seq_generator: SeqGenerator::new(),
            nlmsg_batch: NlmsgBatch::new(),
            nlmsg_recv_buffer: MnlReceiveBuffer::new(MNL_SOCKET_BUFFER_SIZE() as usize),
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
            ban_cache: Cache::builder()
                .initial_capacity(args.cache_initial_capacity)
                .max_capacity(args.cache_max_size)
                .time_to_live(args.ban_base_time.saturating_sub(Duration::from_secs(1)))
                .build_with_hasher(Default::default()),
            recidivism_counts: Cache::builder()
                .initial_capacity(args.cache_initial_capacity)
                .max_capacity(args.cache_max_size)
                .time_to_live(args.ban_ttl)
                .build_with_hasher(Default::default()),
            line_count: 0,
            line_count_start: Instant::now(),
            ban_count: 0,
            ban_count_start: Instant::now(),
            args,
        };

        // Ban some reserved IPs to test configuration and kernel communication.
        info!("Testing bans ...");
        leroy.ban(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))?;
        leroy.ban(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))?;

        info!("Ready");
        Ok(leroy)
    }

    pub fn handle_line(&mut self, line: &Vec<u8>) -> io::Result<()> {
        self.line_count += 1;

        if self
            .ip_rate_limiters
            .as_mut()
            .is_none_or(|l| l.check_key(line).is_err())
        {
            match IpAddr::parse_ascii(line) {
                Ok(ip) => self.ban(ip)?,
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

        Ok(())
    }

    fn ban(&mut self, ip: IpAddr) -> io::Result<()> {
        if self.ban_cache.contains_key(&ip) {
            debug!("{ip} already banned");
            return Ok(());
        }

        let recidivism: u32 = *self.recidivism_counts.get(&ip).unwrap_or(&0) + 1;
        let timeout = self.args.time_to_ban(recidivism);
        info!(
            "Banning {ip} for {}s (recidivism: {recidivism})",
            timeout.as_secs()
        );

        let mut set = NftnlSet::new();
        set.set_table(&self.args.table);
        set.set_name(match ip {
            IpAddr::V4(_) => &self.args.ipv4_set,
            IpAddr::V6(_) => &self.args.ipv6_set,
        });

        let mut elem = NftnlSetElem::new();
        elem.set_key(ip);
        elem.set_timeout(timeout);
        set.add(elem);

        let seq = self.seq_generator.inc();
        self.nlmsg_batch.reset();
        self.nlmsg_batch.begin(seq);
        // Ensure following delete succeeds unconditionally.
        self.nlmsg_batch.set_elems(
            NFT_MSG_NEWSETELEM as u16,
            NFPROTO_INET as u16,
            (NLM_F_CREATE | NLM_F_REQUEST) as u16,
            &set,
            seq,
        );
        // Delete to reset timeout if element already exists.
        self.nlmsg_batch.set_elems(
            NFT_MSG_DELSETELEM as u16,
            NFPROTO_INET as u16,
            (NLM_F_CREATE | NLM_F_REQUEST) as u16,
            &set,
            seq,
        );
        // Add element with new timeout.
        self.nlmsg_batch.set_elems(
            NFT_MSG_NEWSETELEM as u16,
            NFPROTO_INET as u16,
            (NLM_F_CREATE | NLM_F_REQUEST | NLM_F_ACK) as u16,
            &set,
            seq,
        );
        self.nlmsg_batch.end(seq);

        if let Some(socket) = &mut self.socket {
            let bytes = self.nlmsg_batch.as_bytes();
            socket.send(bytes)?;

            let mut seen_enfile = false;
            let port_id = socket.port_id();
            while let Err(err) =
                socket.recv_and_validate(&mut self.nlmsg_recv_buffer, Some(seq), port_id)
            {
                match err.raw_os_error() {
                    Some(libc::EAGAIN) if seen_enfile => return Ok(()), // All errors drained
                    Some(libc::ENFILE) => {
                        // Recoverable. Continue looking for other errors.
                        // Usually sent twice (once for each NFT_MSG_NEWSETELEM) above.
                        if !mem::replace(&mut seen_enfile, true) {
                            error!("Error ENFILE banning {ip}: Set full?");
                        }
                    }
                    Some(libc::ENOENT) if seen_enfile => {
                        warn!("Error ENOENT banning {ip}: Ignoring after ENFILE");
                    }
                    Some(libc::ENOENT) => {
                        error!("Error ENOENT banning {ip}: Table or set not created?");
                        return Err(err);
                    }
                    Some(libc::EPERM) => {
                        error!("Error EPERM banning {ip}: Permission denied");
                        return Err(err);
                    }
                    _ => return Err(err),
                }
            }
        }

        self.ban_cache.insert(ip, ());
        self.recidivism_counts.insert(ip, recidivism);

        self.ban_count += 1;
        if self.ban_count_start.elapsed() > self.args.reporting_ban_time_period {
            info!(
                "Banned {} ips in the past {}s",
                self.ban_count,
                self.ban_count_start.elapsed().as_secs()
            );
            self.ban_count = 0;
            self.ban_count_start = Instant::now();
        }

        Ok(())
    }
}
