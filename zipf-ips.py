#!/usr/bin/env python3

"""
Generate an infinite stream of random IPv4/IPv6 addresses with Zipf distribution
"""

import hashlib
import signal
import socket
import argparse

import numpy as np


def rank_to_ipv4(rank: int) -> str:
    h = hashlib.blake2s(rank.to_bytes(8), digest_size=4).digest()
    return socket.inet_ntop(socket.AF_INET, h)


def rank_to_ipv6(rank: int) -> str:
    h = hashlib.blake2s(rank.to_bytes(8), digest_size=16).digest()
    return socket.inet_ntop(socket.AF_INET6, h)


def rank_to_ip(rank: int, ipv4_only: bool, ipv6_only: bool) -> str:
    if ipv4_only:
        return rank_to_ipv4(rank)
    if ipv6_only:
        return rank_to_ipv6(rank)
    return rank_to_ipv4(rank) if rank & 1 else rank_to_ipv6(rank)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-a", "--alpha", type=float, default=1.5, help="Zipf exponent")
    parser.add_argument("-4", "--ipv4-only", action="store_true")
    parser.add_argument("-6", "--ipv6-only", action="store_true")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()

    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    rng = np.random.default_rng(args.seed)

    try:
        while True:
            for rank in rng.zipf(args.alpha, size=4096):
                print(rank_to_ip(int(rank), args.ipv4_only, args.ipv6_only))
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()
