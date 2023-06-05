#! /bin/env python3

import sys
import socket
from datetime import datetime
import multiprocessing
import os
import argparse
import ipaddress
import textwrap
import time


def scan_port(target: str, port: int, timeout: float = 1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(timeout)

        # returns an error indicator
        result = s.connect_ex((target, port))
        s.close()
        return result

    except Exception as e:
        return e


def _scan(targets: list, ports: list) -> list:
    return [[scan_port(target, port) for port in ports] for target in targets]


def _collect_results(targets, ports, raw_results) -> dict:
    d = {}
    for target, target_results in zip(targets, raw_results):
        d[target] = {}
        for port, result in zip(ports, target_results):
            description = ""
            if result == 0:
                description = "Open"
            elif isinstance(result, int):
                description = f"[errno {result}] " + os.strerror(result)
            else:
                description = str(result)
            d[target][port] = description
    return d


def scan(targets: list, ports: list, processes=12) -> dict:
    results = []

    with multiprocessing.Pool(processes=processes) as pool:
        for target in targets:
            result = pool.apply_async(_scan, ([target], ports))
            results.append(result)

        pool.close()
        pool.join()

    results = [result.get()[0] for result in results]
    return _collect_results(targets, ports, results)


def format_results_str(results) -> list:
    results_str = []
    for target, r in results.items():
        for port, description in r.items():
            results_str.append(f"{target}:{port} {description}")
    return sorted(results_str)

def _parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--ports", type=str, default="11311",
                        help="List of ports, seperated using \",\"")
    parser.add_argument("addresses", nargs="+", help="List of addresses")
    args = parser.parse_args()

    targets = []
    for address in args.addresses:
        try:
            ipaddress.ip_address(address)
        except ValueError:
            print(f"Invalid ip address: {address}")
            sys.exit()
        targets.append(address)

    ports = set()
    for p in args.ports.split(","):
        try:
            port = int(p)
            assert 0 < port < 65536
        except:
            print(f"Invalid port: {p}")
            sys.exit()
        ports.add(port)
    ports = sorted(list(ports))

    return targets, ports


def scan_and_print(targets, ports):
    # Add Banner
    print("-" * 50)
    print(textwrap.fill("Scanning addresses: " +
          ", ".join(targets), subsequent_indent="\t"))
    print(textwrap.fill("Scanning ports: " +
          ", ".join([str(p) for p in ports]), subsequent_indent="\t"))
    print("Scanning started at: " + str(datetime.now()))

    try:
        results = scan(targets, ports)
    except KeyboardInterrupt:
        print("\n Exiting Program !!!!")
        sys.exit()

    print("Scanning ended at: " + str(datetime.now()))
    print("-" * 50)

    print("\n".join(format_results_str(results)))


def main():
    targets, ports = _parse_args()
    scan_and_print(targets, ports)


if __name__ == "__main__":
    main()
