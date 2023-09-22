# Leroy Jenkins

Used when someone needs [to be decisive](https://www.youtube.com/watch?v=mLyOj_QD4a4) amongst [too much planning and inaction](https://www.youtube.com/watch?v=km5FAAQLUT8)

## Building

```sh
cargo +nightly build --release
```

You may need to install the nightly toolchain with `rustup`:

```sh
rustup toolchain install nightly
```

## Usage

*leroyjenkins* reads data from stdin, and assumes each line is an IP address. Use in combination with standard unix tools like `tail -F`. When an IP address shows up too often before its cache times out, it will added to the ipset with the specified timeout.

```sh
tail -F /tmp/ips.log | RUST_LOG=info ./target/release/leroyjenkins --bl-ttl=20 --bl-threshold=100 --ipset-base-time=100 --ipset-ban-ttl=86400 --ipset-ipv6-name=leroy6 --ipset-ipv4-name=leroy4 --reporting-ip-time-period=1 --reporting-ban-time-period=1
```

[!WARNING]
*leroyjenkins* itself does nothing wrt. to your iptables rules. Use iptables (or your firewall of choice) to ban traffic when the IP matches any in the ipset.

[!NOTE]
Must be run with enough privileges to actually add to ipsets. :joy:

## Examples

Because it reads from stdin and this is Unix, you can pipe stuff into it. Use `tail -F`, use `awk`, use `grep` or `rg` or `ag`.

### Dig some lines out of some application log and use them to ban

```sh
tail -F /var/log/app/app.ratelimit.log | ag 'naughty.behaviour' | stdbuf --output=L awk '{print $NF}' | leroyjenkins $LEROY_ARGS
```

### Ban random IPs!

Because it's Unix, use `bash` and `shuf` to ban a random IP every second for an hour with:

```sh
while sleep 1; do echo `shuf -i1-256 -n1`.`shuf -i1-256 -n1`.`shuf -i1-256 -n1`.`shuf -i1-256 -n1`; done | RUST_LOG=info ./target/release/leroyjenkins --bl-ttl=10 --bl-threshold=0 --ipset-base-time=100 --ipset-ban-ttl=3600 --ipset-ipv6-name=leroy6 --ipset-ipv4-name=leroy4 --reporting-ip-time-period=1 --reporting-ban-time-period=1
```
