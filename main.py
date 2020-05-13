#!/usr/bin/env python3
import argparse
import scanEngine
import random
import Data
import time

parser = argparse.ArgumentParser(description="Just a Python Network Scanning Tool.")
group = parser.add_mutually_exclusive_group()
parser.add_argument("targets", nargs='+', help="Hosts and/or Networks comma delimeted.")
group.add_argument("-ns","--no-scan", default=False, help="This option disables TCP Scan. Mutually exclusive with -p", action="store_true")
group.add_argument("-p","--ports", help="Ports can be comma delimeted for specfic ports and dashed for a range.")
parser.add_argument("-t","--threads", type=int, default=300, help="The amount of threads for pyping to use. Default is 300.")
parser.add_argument("-P","--ping", help="Does a ping scan on targets before port scanning.", action="store_true")
args = parser.parse_args()

if args.ports == None:
    args.ports = Data.ports
    random.shuffle(args.ports)
    args.ports = ','.join(args.ports)

scanner = scanEngine.Scanner(args.targets, args.threads, args.ports, args.ping, args.no_scan)
start = time.perf_counter()
scanner.start()
print(f'Full scan took {time.perf_counter() - start:.04f} secs')
print('\a')
