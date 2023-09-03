# Leroy Jenkins
Used when someone needs [to be decisive](https://www.youtube.com/watch?v=mLyOj_QD4a4) amongst [too much planning and inaction](https://www.youtube.com/watch?v=km5FAAQLUT8)

# Use
```
RUST_LOG=info leroyjenkins --ban-log=/tmp/foo.txt --time-to-live=20 --instances-before-ban=100 --first-ban-time=100 --ipv6-set-name leroy6 --ipv4-set-name leroy4 --ip-reporting-time-period=1 --ban-reporting-time-period=1
```

# Info
This program assumes it's able to use `tail -F` to follow a file which will have single IP addresses written to each line. When a given IP address shows up too often before their cache times out, then it will add it to the provided ipset which can be used with iptables to limit traffic
