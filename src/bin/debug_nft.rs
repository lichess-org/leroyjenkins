use std::{error::Error, thread::sleep, time::Duration};

use clap::Parser;
use leroyjenkins::{Args as LeroyArgs, Leroy};
use log::info;

/// Test wrapper for debugging nftables integration with hardcoded IPs
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// IPv4 set name in nftables (in inet table)
    #[arg(long)]
    ipset_ipv4_name: String,

    /// IPv6 set name in nftables (in inet table)
    #[arg(long)]
    ipset_ipv6_name: String,

    /// First ban duration (uses humantime format, e.g., "100s", "5m")
    #[arg(long, default_value = "100s", value_parser = parse_duration)]
    ipset_base_time: Duration,

    /// Recidivism tracking window (uses humantime format, e.g., "1d", "24h")
    #[arg(long, default_value = "1d", value_parser = parse_duration)]
    ipset_ban_ttl: Duration,
}

fn parse_duration(s: &str) -> Result<Duration, humantime::DurationError> {
    s.parse::<humantime::Duration>().map(Into::into)
}

const TEST_IPS: &[&[u8]] = &[
    b"192.0.2.1",    // TEST-NET-1 (RFC 5737)
    b"198.51.100.2", // TEST-NET-2 (RFC 5737)
    b"2001:db8::1",  // IPv6 documentation prefix (RFC 3849)
    b"2001:db8::2",  // IPv6 documentation prefix (RFC 3849)
];

fn main() -> Result<(), Box<dyn Error>> {
    pretty_env_logger::init();

    let args = Args::parse();
    info!("Debug NFT Test Wrapper");
    info!(
        "Config: base_time={}s, ban_ttl={}s",
        args.ipset_base_time.as_secs(),
        args.ipset_ban_ttl.as_secs()
    );
    info!(
        "IPv4 set: {}, IPv6 set: {}",
        args.ipset_ipv4_name, args.ipset_ipv6_name
    );

    let leroy_args = LeroyArgs {
        bl_threshold: 0, // ban-on-sight
        bl_period: Duration::from_secs(0),
        ipset_base_time: args.ipset_base_time,
        ipset_ban_ttl: args.ipset_ban_ttl,
        ipset_ipv4_name: args.ipset_ipv4_name,
        ipset_ipv6_name: args.ipset_ipv6_name,
        reporting_ban_time_period: Duration::from_secs(10),
        reporting_ip_time_period: Duration::from_secs(10),
        cache_initial_capacity: 100000,
        cache_max_size: 500000,
    };

    let mut leroy = Leroy::new(leroy_args)?;

    // Phase 1: First ban (recidivism count = 1)
    info!("========== Phase 1: First ban (recidivism: 1x) ==========");
    for ip in TEST_IPS {
        info!("Adding {}...", String::from_utf8_lossy(ip));
        leroy.handle_line(&ip.to_vec());
    }
    info!("Phase 1 complete. Sleeping 1s before next phase...");
    sleep(Duration::from_secs(1));

    // Phase 2: Second ban (recidivism count = 2)
    info!("========== Phase 2: Second ban (recidivism: 2x) ==========");
    for ip in TEST_IPS {
        info!("Adding {}...", String::from_utf8_lossy(ip));
        leroy.handle_line(&ip.to_vec());
    }
    info!("Phase 2 complete. Sleeping 1s before next phase...");
    sleep(Duration::from_secs(1));

    // Phase 3: Third ban (recidivism count = 3)
    info!("========== Phase 3: Third ban (recidivism: 3x) ==========");
    for ip in TEST_IPS {
        info!("Adding {}...", String::from_utf8_lossy(ip));
        leroy.handle_line(&ip.to_vec());
    }
    info!("Phase 3 complete.");

    info!("========== Test Complete ==========");
    info!(
        "Total operations: {} (4 IPs × 3 phases)",
        TEST_IPS.len() * 3
    );
    info!(
        "Expected ban durations: {}s, {}s, {}s",
        args.ipset_base_time.as_secs(),
        args.ipset_base_time.as_secs() * 2,
        args.ipset_base_time.as_secs() * 3
    );

    Ok(())
}
