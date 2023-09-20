# Leroy Jenkins
Used when someone needs [to be decisive](https://www.youtube.com/watch?v=mLyOj_QD4a4) amongst [too much planning and inaction](https://www.youtube.com/watch?v=km5FAAQLUT8)

# Building
```sh
cargo +nightly build --release
```
You may need to install the nightly toolchain with rustup:
```sh
rustup toolchain install nightly
```

# Usage
NOTE: must be run with enough privileges to actually create and add to ipsets. :joy:
```sh
RUST_LOG=info ./target/release/leroyjenkins --bl-file=/tmp/foo.txt --bl-ttl=20 --bl-threshold=100 --ipset-base-time=100 --ipset-ban-ttl=86400 --ipset-ipv6-name=leroy6 --ipset-ipv4-name=leroy4 --reporting-ip-time-period=1 --reporting-ban-time-period=1
```

# Info
This program assumes it's able to use `tail -F` to follow a file which will have single IP addresses written to each line. When a given IP address shows up too often before their cache times out, then it will add it to the provided ipset which can be used with iptables to limit traffic
