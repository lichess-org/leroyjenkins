# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

leroyjenkins is a lightweight IP banning tool that reads IP addresses from stdin and automatically manages nftables sets based on configurable rate limits and recidivism tracking. It's designed for high-performance DDoS mitigation, reading from log streams and dynamically adding repeat offenders to nftables sets with exponentially increasing ban durations.

## Building and Testing

**Build (requires nightly):**
```sh
cargo +nightly build --release
```

**Run benchmarks:**
```sh
cargo +nightly bench
```

**Run tests:**
```sh
cargo +nightly test
```

This project requires Rust nightly due to the `addr_parse_ascii` feature (see src/lib.rs:1).

## Architecture

### Core Components

**src/main.rs**: Entry point that reads lines from stdin, parses them as IP addresses, and passes them to the Leroy handler. Uses mimalloc as the global allocator for performance.

**src/lib.rs**: Contains the main `Leroy` struct and business logic:
- **Rate limiting**: Uses `KeyedLimiter` wrapper around `governor` crate to track IPs and apply rate limits based on `--bl-threshold` and `--bl-period`
- **Nftables management**: Maintains separate nftables sessions for IPv4/IPv6 via `ByIpFamily<NftSession>`
- **Recidivism tracking**: Two caches using `mini-moka`:
  - `ipset_cache`: Short-lived cache to prevent duplicate nftables adds (TTL: ipset_base_time - 1s)
  - `recidivism_counts`: Long-lived cache tracking how many times an IP has been banned (TTL: ipset_ban_ttl)
- **Progressive banning**: Ban duration = ipset_base_time × recidivism_count (linear escalation)

**src/nft_session.rs**: Wrapper around nftables for managing ban sets:
- **NftSession**: Mimics ipset::Session API for easier migration from rust-ipset
- **Batch operations**: Uses nftables batch API to add elements with individual timeouts
- **Set validation**: Queries ruleset on startup to ensure table and sets exist
- **Dry-run support**: Can skip apply_ruleset for testing without privileges

**src/keyed_limiter.rs**: Custom unsync (single-threaded) implementation of a keyed rate limiter using `governor`. Includes automatic garbage collection that triggers when the internal HashMap reaches a threshold, removing stale entries and shrinking to fit.

**src/ip_family.rs**: Simple abstraction for handling IPv4/IPv6 dual-stack operations. The `ByIpFamily<T>` struct holds separate instances for each protocol family.

### Key Design Decisions

**Performance optimizations:**
- Uses FxHasher (non-cryptographic) instead of default hasher for speed
- Custom unsync state store in KeyedLimiter (no thread-safety overhead)
- Pre-sized caches based on `--cache-initial-capacity` to avoid allocations during attacks
- Lazy GC in rate limiter to batch HashMap cleanup
- mimalloc allocator

**Dual caching strategy:**
- `ipset_cache` prevents redundant nftables operations (nftables already tracks this, but cache avoids syscalls)
- `recidivism_counts` implements the "ban longer each time" logic

**stdin-based architecture**: Designed to work in Unix pipelines with tools like `tail -F`, `awk`, `grep`, enabling flexible log parsing without hard-coding log formats.

## Common CLI Arguments

```sh
--bl-threshold=100           # Events before ban (use 0 for ban-on-sight)
--bl-period=1m              # Time window for threshold
--ipset-base-time=100s      # First ban duration
--ipset-ban-ttl=1d          # How long to remember recidivism
--ipset-ipv4-name=leroy4    # IPv4 set name in nftables (must exist)
--ipset-ipv6-name=leroy6    # IPv6 set name in nftables (must exist)
--dry-run                   # Test without touching nftables
```

The nftables table `leroyjenkins` and sets must be created before running (unless using `--dry-run`). The tool will verify they exist on startup.

Example nftables setup:
```sh
nft add table ip leroyjenkins
nft add table ip6 leroyjenkins
nft add set ip leroyjenkins leroy4 '{ type ipv4_addr; flags timeout; }'
nft add set ip6 leroyjenkins leroy6 '{ type ipv6_addr; flags timeout; }'
```

## Dependencies

- `nftables`: Rust bindings for nftables via libnftables-json (version 0.6)
- `governor`: Rate limiting (version 0.6.0)
- `mini-moka`: Fast unsync cache (version 0.10.2)
- `rustc-hash`: FxHasher (version 1.1.0)
- `mimalloc`: Memory allocator (version 0.1.39)
- `criterion`: Benchmarking (dev dependency)
