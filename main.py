#!/usr/bin/env python3
'''A Python Network Scanner'''
import random
import time
import scanEngine
import Data.portlist
import Data

class Pymap(object):
    """A Class Interface for Pymap if it imported as a python module instead of run from commandline
    when I have figured out how to support it being imported."""
    def __init__(self, targets, threads=300, ports=None,
                 ping=False, no_scan=False, service_scan=False):
        self.targets = targets
        self.threads = threads
        if ports is None:
            self.ports = Data.portlist.ports
        else:
            self.ports = ports
        self.ping = ping
        self.no_scan = no_scan
        self.service_scan = service_scan

    def startscan(self):
        '''Starts the scanning engine'''
        scanner = scanEngine.Scanner(self.targets, self.threads, self.ports,
                                     self.ping, self.no_scan, self.service_scan)
        scanner.start()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Just a Python Network Scanning Tool.")
    group = parser.add_mutually_exclusive_group()
    parser.add_argument("targets", nargs='+', help="Hosts and/or Networks space delimeted.")
    group.add_argument("-ns", "--no-scan", default=False,
                       help="This option disables TCP Scan. Mutually exclusive with -p",
                       action="store_true")
    group.add_argument("-p", "--ports",
                       help="Ports are comma delimeted for specfic ports and dashed for a range.")
    parser.add_argument("-t", "--threads", type=int, default=300,
                        help="The amount of threads for pyping to use. Default is 300.")
    parser.add_argument("-P", "--ping", help="Does a ping scan on targets before port scanning.",
                        action="store_true")
    parser.add_argument("-sV", "--service-scan", help="Enables a light service enumeration scan.",
                        action="store_true")
    args = parser.parse_args()
    if args.ports is None:
        args.ports = Data.portlist.ports
        random.shuffle(args.ports)
        args.ports = ','.join(args.ports)

    cliScanner = scanEngine.Scanner(args.targets, args.threads, args.ports, args.ping,
                                    args.no_scan, args.service_scan)
    start = time.perf_counter()
    cliScanner.start()
    print(f'Full scan took {time.perf_counter() - start:.04f} secs')
