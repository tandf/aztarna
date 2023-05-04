#!/usr/bin/env python
# -*- coding: utf-8 -*-
import asyncio
import logging
import re
from argparse import ArgumentParser
import argcomplete
import uvloop

from aztarna.ros.industrial.scanner import ROSIndustrialScanner
from aztarna.industrialrouters.scanner import IndustrialRouterAdapter

# asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

logging.getLogger(__name__).setLevel(logging.DEBUG)

def main():
    """
    Main method
    """
    logging.basicConfig(level=logging.INFO, format="%(name)s - %(message)s")
    logger = logging.getLogger(__name__)
    parser = ArgumentParser(description='Aztarna, a reconnaissance tool for robots and robot components.')
    parser.add_argument('-t', '--type', help='<ROS/ros/SROS/sros/ROS2/ros2/IROUTERS/irouters> Scan ROS, SROS, ROS2 hosts or Industrial routers', required=True)
    parser.add_argument('-a', '--address', help='Single address or network range to scan.')
    parser.add_argument('-p', '--ports', help='Ports to scan (format: 13311 or 11111-11155 or 1,2,3,4)', default='11311')
    parser.add_argument('-i', '--input_file', help='Input file of addresses to use for scanning')
    parser.add_argument('-o', '--out_file', help='Output file for the results')
    parser.add_argument('-e', '--extended', help='Extended scan of the hosts', action='store_true')
    parser.add_argument('-b', '--bus', help='Get node transport/topic (bus) statistics and connection information (-e must also be selected)', action='store_true')
    parser.add_argument('-m', '--parameters', help='Get parameter name information', action='store_true')
    parser.add_argument('-f', '--failures', help='Keep track of information about failures', action='store_true')
    parser.add_argument('-c', '--check', help='Try TCP SYN scan on a high-numbered normally-closed port(s) to check if address may respond to any port (specify number of (random) high-numbered nomrally-closed ports to scan)', default=0, type=int)
    parser.add_argument('-s', '--save', help='Save ROS system information to a new file with unique filename (specify format to save information: output, JSON, YAML, or all; if multiple but not all, separate with commas)', default='none')
    parser.add_argument('-w', '--when', help='When to create output files, only at the end (default) or after every scanned potential host port: (end, every)', default='end')
    parser.add_argument('-n', '--handle', help='Handle/Catch unexpected critical failure excecptions to allow scan to continue while creating logs of failure(s). Otherwise, if not selected, allow exception to propagate', action='store_true')
    parser.add_argument('-r', '--rate', help='Maximum simultaneous network connections', default=100, type=int)
    parser.add_argument('-d', '--domain', help='ROS 2 DOMAIN ID (ROS_DOMAIN_ID environmental variable). Only applies to ROS 2.', type=int)
    parser.add_argument('--daemon', help='Use rclpy daemon (coming from ros2cli).', action='store_true')
    parser.add_argument('--hidden', help='Show hidden ROS 2 nodes. By default filtering _ros2cli*', action='store_true')
    parser.add_argument('--shodan', help='Use shodan for the scan types that support it.', action='store_true')
    parser.add_argument('--api-key', help='Shodan API Key')
    parser.add_argument('--verbose', help='Verbose output')
    parser.add_argument('--passive', help='Passive search for ROS2', action='store_true')
    argcomplete.autocomplete(parser)
    args = parser.parse_args()
    try:
        if args.type == 'ROS' or args.type == 'ros':
            from aztarna.ros.ros import ROSScanner
            scanner = ROSScanner()
        elif args.type == 'SROS' or args.type == 'sros':
            from aztarna.ros.sros import SROSScanner
            scanner = SROSScanner()
        elif args.type == 'IROUTERS' or args.type == 'irouters':
            scanner = IndustrialRouterAdapter()
            if args.shodan is True:
                scanner.use_shodan = True
                scanner.shodan_api_key = args.api_key
                scanner.initialize_shodan()
        elif args.type.upper() == 'ROSIN':
            scanner = ROSIndustrialScanner()
        elif args.type.upper() == 'ROS2':
            from aztarna.ros.ros2.scanner import ROS2Scanner
            scanner = ROS2Scanner()
        else:
            logger.critical('Invalid type selected')
            return
        pipe = False
        if args.input_file:
            try:
                scanner.load_from_file(args.input_file)
            except FileNotFoundError:
                logger.critical('Input file not found')
        elif args.address:
            scanner.load_range(args.address)
        else:
            if args.type.upper() not in ['ROS2']:
                pipe = True


        # TODO Implement a regex for port argument
        try:
            scanner.ports = range(int(args.ports.split('-')[0]), int(args.ports.split('-')[1]))
        except:
            try:
                scanner.ports = [int(port) for port in args.ports.split(',')]
            except:
                try:
                    scanner.ports.append(int(args.ports))
                except Exception as e:
                    logger.error('[-] Error: ' + str(e))


        scanner.save_format = args.save.split(',')
        for entry in scanner.save_format:
            if (entry not in ['none', 'output', 'json', 'JSON', 'yaml', 'YAML', 'all']):
                logger.critical('Invalid save format selected')
                return
        if ((scanner.when == 'end') or (scanner.when == 'every')):
            scanner.when = args.when
        else:
            logger.critical('Invalid "when" option selected')
            return

        scanner.extended = args.extended
        scanner.bus = args.bus
        scanner.parameters = args.parameters
        scanner.failures = args.failures
        scanner.check = args.check
        scanner.handle = args.handle
        scanner.out_file = args.out_file
        scanner.rate = args.rate
        scanner.domain = args.domain
        if args.daemon is True:
            scanner.use_daemon = True
        if args.hidden is True:
            scanner.hidden = True
        if args.passive is True:
            scanner.passive = True

        if pipe:
            scanner.scan_pipe_main()
        else:
            scanner.scan()

        if (args.when == 'end'):
            if args.out_file:
                scanner.write_to_file(args.out_file)
            else:
                if ('none' not in scanner.save_format):
                    scanner.catch_save_to_file(scanner.save_format, address_port=[f'{host.address}:{host.port}' for host in scanner.hosts])
                elif args.extended is True:
                    scanner.catch_print_results(address_port=[f'{host.address}:{host.port}' for host in scanner.hosts])

    except Exception as e:
        logger.critical('Exception occurred during execution')
        raise e


if __name__ == '__main__':
    main()
