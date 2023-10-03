use std::{hint::black_box, net::Ipv4Addr, time::Duration};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use leroyjenkins::{Args, Leroy};
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn make_leroy() -> Leroy {
    black_box(
        Leroy::new(Args {
            bl_threshold: 10,
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
        .unwrap(),
    )
}

fn dry_run(c: &mut Criterion) {
    let mut group = c.benchmark_group("dry_run");

    group.throughput(Throughput::Elements(1));
    group.bench_function("single_ipv4", |b| {
        let mut leroy = make_leroy();
        b.iter(|| {
            leroy.handle_line(&black_box(b"142.250.185.142".to_vec()));
        })
    });

    group.throughput(Throughput::Elements(1));
    group.bench_function("single_ipv6", |b| {
        let mut leroy = make_leroy();
        b.iter(|| {
            leroy.handle_line(&black_box(b"2a00:1450:4001:813::200e".to_vec()));
        })
    });

    group.throughput(Throughput::Elements(5));
    group.bench_function("hammer_few_ips", |b| {
        let mut leroy = make_leroy();
        b.iter(|| {
            leroy.handle_line(&black_box(b"2001:41d0:307:b200::".to_vec()));
            leroy.handle_line(&black_box(b"54.38.164.114".to_vec()));
            leroy.handle_line(&black_box(b"152.228.187.173".to_vec()));
            leroy.handle_line(&black_box(b"54.38.164.114".to_vec()));
            leroy.handle_line(&black_box(b"54.38.164.114".to_vec()));
        })
    });

    group.throughput(Throughput::Elements(1));
    group.bench_function("unique_ips", |b| {
        let mut leroy = make_leroy();
        let mut bits = 0;
        b.iter(|| {
            leroy.handle_line(&black_box(Ipv4Addr::from(bits).to_string().into_bytes()));
            bits += 3733;
        })
    });

    group.throughput(Throughput::Elements(3 * 20));
    group.bench_function("hammer_many_ips", |b| {
        let mut leroy = make_leroy();
        let mut bits = 0;
        b.iter(|| {
            for _ in 0..20 {
                leroy.handle_line(&black_box(Ipv4Addr::from(bits).to_string().into_bytes()));
                leroy.handle_line(&black_box(Ipv4Addr::from(!bits).to_string().into_bytes()));
                leroy.handle_line(&black_box(
                    Ipv4Addr::from(bits.swap_bytes()).to_string().into_bytes(),
                ));
            }
            bits += 3733;
        })
    });
}

criterion_group!(benches, dry_run);
criterion_main!(benches);
