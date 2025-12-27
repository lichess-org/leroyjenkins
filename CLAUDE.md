# CLAUDE.md

This file provides guidance to Claude Code (https://claude.ai/code) when working with code in this repository.

- When reporting information to me, be extremely concise and sacrifice
  grammar for the sake of concision.
- To finalize a set of changes, ensure all tests pass and benchmarks runs.
  Format code.

## Project Overview

leroyjenkins is a lightweight IP banning tool that reads IP addresses from stdin and automatically manages nftables sets based on configurable rate limits and recidivism tracking. It's designed for high-performance DDoS mitigation, reading from log streams and dynamically adding repeat offenders to nftables sets with increasing ban durations.

## Building and Testing

**Build (requires nightly):**
```sh
cargo +nightly build --release
```

**Format code:**
```sh
cargo +nightly fmt
```

**Run tests:**
```sh
cargo +nightly test
```

**Run benchmarks:**
```sh
cargo +nightly bench
```

This project requires Rust nightly for the `addr_parse_ascii` feature.

## Architecture

### Core Components

**src/main.rs**: Entry point that reads lines from stdin, parses them as IP addresses, and passes them to the Leroy handler.

**src/lib.rs**: Contains the main `Leroy` struct and business logic:
- **Rate limiting**: Uses `KeyedLimiter` wrapper around `governor` crate to track IPs and apply rate limits based on `--bl-threshold` and `--bl-period`
- **Nftables management**: Holds `mnl::Socket` to communicate with the kernel
- **Recidivism tracking**: Two caches using `mini-moka`:
  - `ban_cache`: Short-lived cache to prevent duplicate nftables adds (TTL: `ban_base_time` - 1s)
  - `recidivism_counts`: Long-lived cache tracking how many times an IP has been banned (TTL: `ban_ttl`)
- **Progressive banning**: Ban duration = `--ban-base-time` × recidivism_count (linear escalation)

**src/keyed_limiter.rs**: Custom unsync (single-threaded) implementation of a keyed rate limiter using `governor`. Includes automatic garbage collection that triggers when the internal HashMap reaches a threshold, removing stale entries.

### Design Decisions

**Stdin-based**: Designed to work in Unix pipelines with tools like `tail -F`, `awk`, `grep`, enabling flexible log parsing without hard-coding log formats.

**Caching strategy:**
- `ban_cache` prevents redundant nftables operations (nftables already tracks this, but cache avoids syscalls)
- `recidivism_counts` implements the "ban longer each time" logic (state is forgotten when Leroy restarts)

**Performance optimizations:**
- Custom unsync state store in `KeyedLimiter` (no thread-safety overhead)
- Pre-sized caches based on `--cache-initial-capacity` to avoid allocations during attacks
- Lazy GC in rate limiter
- Uses `FxHasher` (non-cryptographic) instead of default hasher for speed
- `MiMalloc` allocator

## Common CLI Arguments

```
--bl-threshold=100   # Events before ban (use 0 for ban-on-sight)
--bl-period=1m       # Time window for threshold
--ban-base-time=100s # First ban duration
--ban-ttl=1d         # How long to remember recidivism
--table=leroy        # Name of table in nftables (must exist with protocol family inet)
--ipv4-set=leroy4    # IPv4 set name in nftables (must exist)
--ipv6-set=leroy6    # IPv6 set name in nftables (must exist)
--dry-run            # Test without touching nftables
```

The nftables table `leroyjenkins` and sets must be created before running (unless using `--dry-run`). The tool will verify they exist on startup.

Example nftables setup:

```sh
nft add table inet leroy
nft add set inet leroy leroy4 '{ type ipv4_addr; flags timeout; }'
nft add set inet leroy leroy6 '{ type ipv6_addr; flags timeout; }'
```

Check state of the table and contents of the sets:

```sh
nft list table inet leroy
```

## Important dependencies

- `nftnl-sys` and `mnl-sys`: Rust bindings for libnftnl and libmnl, to communicate with nftables
- `governor`: Rate limiting
- `mini-moka`: Fast unsync cache
