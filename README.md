# Leroy Jenkins

Follow ban logs to manage ip sets in nftables -- used when someone needs [to be decisive](https://www.youtube.com/watch?v=mLyOj_QD4a4) amongst [too much planning and inaction](https://www.youtube.com/watch?v=km5FAAQLUT8).

## Usage

*leroyjenkins* reads data from stdin, and assumes each line is an IP address. Use in combination with standard unix tools like `tail -F`. When an IP address shows up too often before its cache times out, it will be added to the nftables set with the specified timeout.

```sh
tail -F /tmp/ips.log | RUST_LOG=info ./target/release/leroyjenkins --bl-period=1m --bl-threshold=100 --ban-base-time=100s --ban-ttl=1d --table=leroy --ipv6-set=leroy6 --ipv4-set=leroy4
```

> [!NOTE]
> *leroyjenkins* itself does nothing to your firewall rules. Use nftables rules similar to the ones below.

## Building

```sh
cargo +nightly build --release
```

## Setup

Before running, create the nftables table and sets, leroy expects these to exist:

```
#!/usr/sbin/nft -f

table inet leroy {
    # define our sets
    set leroy4 {
        type ipv4_addr;
        timeout 60s;
        size 65536;
        flags timeout;
    }

    set leroy6 {
        type ipv6_addr;
        timeout 60s;
        size 65536;
        flags timeout;
    }

    # arbitrary rules using the sets
    chain input {
        # accept everybody by default in this chain, with a really
        # high priority so that we can reject them as early as
        # possible in the netfilter system
        type filter hook input priority -900; policy accept;

        # but if you match, you're out
        ip  saddr @leroy4 counter name leroyed reject with tcp reset
        ip6 saddr @leroy6 counter name leroyed reject with tcp reset
    }

    chain output {
        # accept everybody by default in this chain, with a really
        # high priority so that we can reject them as early as
        # possible in the netfilter system
        type filter hook output priority -900; policy accept;

        # but if you match, you're out
        ip  daddr @leroy4 reject with tcp reset
        ip6 daddr @leroy6 reject with tcp reset
    }
}
```

## Examples

Because it reads from stdin and this is Unix, you can pipe stuff into it. Use `tail -F`, use `awk`, use `grep` or `rg` or `ag`.

### Dig some lines out of some application log and use them to ban

```sh
tail -F /var/log/app/app.ratelimit.log | ag 'naughty.behaviour' | stdbuf --output=L awk '{print $NF}' | RUST_LOG=info ./target/release/leroyjenkins --bl-period=1m --bl-threshold=100 --ban-base-time=100s --ban-ttl=1d
```

### Stress test with an infinite stream of random IPs

```sh
./zipf-ips.py | RUST_LOG=info ./target/release/leroyjenkins --bl-period=10s --bl-threshold=0 --ban-base-time=100s --ban-ttl=1h --table leroy --ipv4-set=leroy4 --ipv6-set=leroy6
```

## License

*leroyjenkins* is licensed under the GLP 3 (or any later version at your option).
