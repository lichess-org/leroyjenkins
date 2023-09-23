use std::{num::NonZeroU32, time::Duration};

use criterion::{criterion_group, criterion_main, Criterion};
use leroyjenkins::{Args, Leroy};

fn hammer_few_ips(c: &mut Criterion) {
    let mut leroy = Leroy::new(Args {
        bl_threshold: NonZeroU32::new(10).unwrap(),
        bl_period: Duration::from_secs(5),
        ipset_base_time: Duration::from_secs(30),
        ipset_ban_ttl: Duration::from_secs(60 * 60),
        ipset_ipv4_name: "leroy4".to_owned(),
        ipset_ipv6_name: "leroy6".to_owned(),
        reporting_ip_time_period: Duration::from_secs(1),
        reporting_ban_time_period: Duration::from_secs(1),
        cache_initial_capacity: 100000,
        cache_max_size: 500000,
        dry_run: true,
    })
    .unwrap();

    c.bench_function("hammer few ips", |b| {
        b.iter(|| {
            for _ in 0..10 {
                leroy.handle_line(b"2001:41d0:307:b200::".to_vec());
                leroy.handle_line(b"54.38.164.114".to_vec());
                leroy.handle_line(b"152.228.187.173".to_vec());
                leroy.handle_line(b"54.38.164.114".to_vec());
            }
        })
    });
}

criterion_group!(benches, hammer_few_ips);
criterion_main!(benches);
